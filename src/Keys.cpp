// GetKey's chain: the caller's KeyProvider, the keys found in this process, the cache file, then
// the finders (KeyFinders.cpp). Never log a key's bytes.

#include <wolff/Keys.h>

#include "KeyFinders.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <ShlObj.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cwctype>
#include <format>
#include <fstream>
#include <mutex>
#include <optional>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")

namespace wolff
{
namespace
{
    using keyfind::Bytes;

    // WWII's key, published by Scobalula (s2_ff_killer, public domain), at a pinned commit
    constexpr const wchar_t* S2KeyUrl =
        L"https://raw.githubusercontent.com/Scobalula/s2_ff_killer/717e416fde9ea1c3ae093b2dd0301fe4ededaae5/s2_ff_killer/Key.h";

    struct KeySpec
    {
        std::string_view Id;
        const char* Game;
        std::vector<const wchar_t*> Exes;   // the files the key is read from (none: fetched)
        std::string_view Sha256;            // the key's known hash
    };

    const std::vector<KeySpec>& Specs()
    {
        static const std::vector<KeySpec> S = {
            { keys::T6Salsa20, "Black Ops II", { L"t6mp.exe", L"t6zm.exe", L"t6sp.exe" },
              "117ea16e4fe68b6fb6cefe7c4e81cbf20c6536283b6832b6b4e95d39f2739ad6" },
            { keys::CodolRsa, "Call of Duty Online", { L"codoMP_client_shipRetail.exe" },
              "3a2f7891ac98f1fdf6a9a221c5586725157df270d6831e0ff82c383cd262cbb5" },
            { keys::CodolFileAes, "Call of Duty Online", { L"codoMP_client_shipRetail.exe" },
              "1e22b44436289a94fc0f68048ee4c0fb439b28c59adcf0a7c6d21442203e5c65" },
            { keys::S2RsaPrivate, "WWII", {}, "a4ccba8684f1fa6c80609d59495a9dbc452f998fa18bff6251d7c2f79d06cff1" },
        };
        return S;
    }

    const KeySpec* Spec(std::string_view Id)
    {
        for (const auto& S : Specs())
            if (S.Id == Id) return &S;
        return nullptr;
    }

    std::string ExeList(const KeySpec& S)
    {
        std::string Out;
        for (const auto* E : S.Exes)
            Out += (Out.empty() ? "" : ", ") + std::filesystem::path(E).string();
        return Out;
    }

    // Where a key came from: an exe as it was when the key was read (a game update finds it again),
    // or a URL
    struct Stamp
    {
        std::wstring Source;   // normalised, lower case
        uint64_t Size = 0;
        uint64_t WriteTime = 0;
        bool operator==(const Stamp&) const = default;
    };

    std::wstring Normal(const std::filesystem::path& P)
    {
        std::error_code Ec;
        auto A = std::filesystem::absolute(P, Ec).lexically_normal().wstring();
        std::transform(A.begin(), A.end(), A.begin(), [](wchar_t C) { return (wchar_t)std::towlower(C); });
        return A;
    }

    std::optional<Stamp> FileStamp(const std::filesystem::path& Exe)
    {
        WIN32_FILE_ATTRIBUTE_DATA A;
        if (!GetFileAttributesExW(Exe.c_str(), GetFileExInfoStandard, &A) || (A.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            return std::nullopt;
        return Stamp{ Normal(Exe), ((uint64_t)A.nFileSizeHigh << 32) | A.nFileSizeLow,
                      ((uint64_t)A.ftLastWriteTime.dwHighDateTime << 32) | A.ftLastWriteTime.dwLowDateTime };
    }

    struct Entry
    {
        std::string Id;
        Stamp From;
        Bytes Key;
    };

    std::mutex Lock;
    std::vector<Entry> Found;   // this process's

    const Entry* Lookup(const std::vector<Entry>& In, std::string_view Id, const Stamp& From)
    {
        for (const auto& E : In)
            if (E.Id == Id && E.From == From) return &E;
        return nullptr;
    }

    void Remember(std::vector<Entry>& In, Entry E)
    {
        std::erase_if(In, [&](const Entry& X) { return X.Id == E.Id && X.From.Source == E.From.Source; });
        In.push_back(std::move(E));
    }

    // ------------------------------------------------------------------ the cache file
    std::string Hex(const Bytes& B)
    {
        static const char* H = "0123456789abcdef";
        std::string S;
        for (const uint8_t C : B) S += H[C >> 4], S += H[C & 15];
        return S;
    }
    bool Unhex(const std::string& S, Bytes& Out)
    {
        if (S.size() % 2) return false;
        Out.clear();
        for (size_t I = 0; I < S.size(); I += 2)
        {
            const auto V = [](char C) { return C >= '0' && C <= '9' ? C - '0' : C >= 'a' && C <= 'f' ? C - 'a' + 10 : -1; };
            const int A = V(S[I]), B = V(S[I + 1]);
            if (A < 0 || B < 0) return false;
            Out.push_back((uint8_t)(A * 16 + B));
        }
        return !Out.empty();
    }
    std::wstring Wide(const std::string& Utf8) { return std::filesystem::path(std::u8string(Utf8.begin(), Utf8.end())).wstring(); }
    std::string Utf8(const std::wstring& W)
    {
        const auto U = std::filesystem::path(W).u8string();
        return std::string(U.begin(), U.end());
    }

    std::vector<Entry> ReadCache(const std::filesystem::path& File)
    {
        std::vector<Entry> Out;
        std::ifstream F(File, std::ios::binary);
        if (!F) return Out;
        const auto J = nlohmann::json::parse(F, nullptr, false);
        if (!J.is_object() || J.value("format", "") != "wolff-keys" || !J.contains("keys") || !J["keys"].is_array()) return Out;
        for (const auto& K : J["keys"])
        {
            if (!K.is_object()) continue;
            Entry E;
            E.Id = K.value("id", "");
            E.From.Source = Wide(K.value("source", ""));
            E.From.Size = K.value("size", (uint64_t)0);
            E.From.WriteTime = K.value("write_time", (uint64_t)0);
            if (E.Id.empty() || E.From.Source.empty() || !Unhex(K.value("key", ""), E.Key)) continue;
            Out.push_back(std::move(E));
        }
        return Out;
    }

    // Read, merged, written whole through a temporary file (another process may write it too)
    void WriteCache(const std::filesystem::path& File, const std::vector<Entry>& New)
    {
        auto All = ReadCache(File);
        for (const auto& E : New) Remember(All, E);
        nlohmann::json Keys = nlohmann::json::array();
        for (const auto& E : All)
        {
            nlohmann::json K = { { "id", E.Id }, { "source", Utf8(E.From.Source) } };
            if (E.From.Size) K["size"] = E.From.Size;
            if (E.From.WriteTime) K["write_time"] = E.From.WriteTime;
            K["key"] = Hex(E.Key);
            Keys.push_back(std::move(K));
        }
        const nlohmann::json J = { { "format", "wolff-keys" }, { "version", 1 }, { "keys", Keys } };
        std::error_code Ec;
        std::filesystem::create_directories(File.parent_path(), Ec);
        auto Tmp = File;
        Tmp += L"." + std::to_wstring(GetCurrentProcessId()) + L".tmp";
        {
            std::ofstream F(Tmp, std::ios::binary | std::ios::trunc);
            F << J.dump(1);
            if (!F) return;
        }
        if (!MoveFileExW(Tmp.c_str(), File.c_str(), MOVEFILE_REPLACE_EXISTING)) std::filesystem::remove(Tmp, Ec);
    }

    std::filesystem::path CacheFileOf(const KeyOptions& O) { return O.CacheFile.empty() ? DefaultKeyCacheFile() : O.CacheFile; }

    // ------------------------------------------------------------------ validation
    // A Black Ops 2 fast file of the install, to check a key whose hash is not the known one
    std::filesystem::path SomeT6FastFile(const std::filesystem::path& Install)
    {
        std::error_code Ec;
        for (auto It = std::filesystem::recursive_directory_iterator(Install / "zone", Ec);
             !Ec && It != std::filesystem::recursive_directory_iterator(); It.increment(Ec))
        {
            if (It.depth() > 1) It.disable_recursion_pending();
            if (It->is_regular_file(Ec) && It->path().extension() == ".ff") return It->path();
        }
        return {};
    }

    bool Known(const KeySpec& S, const Bytes& K) { return keyfind::Sha256Hex(K.data(), K.size()) == S.Sha256; }

    // ------------------------------------------------------------------ the finders
    // The keys Install's exe (or the URL) gives for Id, checked; Id's first. Error when none.
    bool FindFrom(const KeySpec& S, const std::filesystem::path& Exe, const std::filesystem::path& Install,
                  const std::filesystem::path& CheckFile, std::vector<std::pair<std::string, Bytes>>& Out, std::string& Error)
    {
        Out.clear();
        if (S.Id == keys::T6Salsa20)
        {
            std::vector<Bytes> Candidates;
            if (!keyfind::T6FromExe(Exe, Candidates, Error)) return false;
            const auto Check = CheckFile.empty() ? SomeT6FastFile(Install) : CheckFile;
            for (const auto& K : Candidates)
                if (Known(S, K) || (!Check.empty() && FastFileInternal::T6KeyOpens(K.data(), K.size(), Check)))
                {
                    Out.emplace_back(std::string(S.Id), K);
                    return true;
                }
            Error = std::format("{} key candidate(s) in {}, none known or opening {}", Candidates.size(), Exe.filename().string(),
                                Check.empty() ? "a zone (none found)" : Check.filename().string());
            return false;
        }
        if (S.Id == keys::CodolRsa || S.Id == keys::CodolFileAes)
        {
            Bytes Rsa, FileKey;
            if (!keyfind::CodolFromExe(Exe, Rsa, FileKey, Error)) return false;
            // the key pair agrees (checked when found); a hash not the known one also needs the
            // file key's seal to have opened with it
            const bool RsaOk = Known(*Spec(keys::CodolRsa), Rsa) || !FileKey.empty();
            if (!RsaOk)
            {
                Error = "the RSA key in " + Exe.filename().string() + " is not the known one and opens no seal";
                return false;
            }
            Out.emplace_back(std::string(keys::CodolRsa), Rsa);
            if (!FileKey.empty()) Out.emplace_back(std::string(keys::CodolFileAes), FileKey);
            if (S.Id == keys::CodolFileAes && FileKey.empty())
            {
                Error = "no sealed file key beside the RSA key in " + Exe.filename().string();
                return false;
            }
            if (S.Id == keys::CodolFileAes) std::swap(Out.front(), Out.back());
            return true;
        }
        if (S.Id == keys::S2RsaPrivate)
        {
            Bytes Der;
            if (!keyfind::S2FromUrl(S2KeyUrl, Der, Error)) return false;
            if (!Known(S, Der))
            {
                Error = "the downloaded key is not the published one (its SHA-256 differs)";
                return false;
            }
            Out.emplace_back(std::string(S.Id), Der);
            return true;
        }
        Error = "Wolff does not know where to find it";
        return false;
    }

    bool IsFile(const std::filesystem::path& P)
    {
        std::error_code Ec;
        return std::filesystem::is_regular_file(P, Ec);
    }
}

std::filesystem::path DefaultKeyCacheFile()
{
    PWSTR Local = nullptr;
    std::filesystem::path Root;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &Local))) Root = Local;
    CoTaskMemFree(Local);
    if (Root.empty()) Root = std::filesystem::temp_directory_path();
    return Root / "wolff" / "keys.json";
}

std::filesystem::path FindKeyInstall(std::string_view Id, const std::filesystem::path& From)
{
    const KeySpec* S = Spec(Id);
    if (S == nullptr || S->Exes.empty() || From.empty()) return {};
    std::error_code Ec;
    std::filesystem::path Dir = std::filesystem::absolute(From, Ec);
    if (!std::filesystem::is_directory(Dir, Ec)) Dir = Dir.parent_path();
    for (; !Dir.empty(); Dir = Dir.parent_path())
    {
        for (const auto* Exe : S->Exes)
            if (IsFile(Dir / Exe)) return Dir;
        if (Dir == Dir.parent_path()) break;
    }
    return {};
}

bool FindKey(std::string_view Id, const std::filesystem::path& Install, std::vector<uint8_t>& Out, std::string& Error,
             const KeyOptions& Options, const std::filesystem::path& CheckFile)
{
    Out.clear();
    const KeySpec* S = Spec(Id);
    if (S == nullptr)
    {
        Error = std::format("Wolff does not know the key '{}'", Id);
        return false;
    }
    std::vector<std::pair<std::string, Bytes>> Keys;
    if (S->Exes.empty())
    {
        if (!Options.Network)
        {
            Error = "network access is off";
            return false;
        }
        if (!FindFrom(*S, {}, {}, CheckFile, Keys, Error)) return false;
        Out = Keys.front().second;
        return true;
    }
    std::string Last = "no " + ExeList(*S) + " in " + Install.string();
    for (const auto* Exe : S->Exes)
        if (IsFile(Install / Exe) && FindFrom(*S, Install / Exe, Install, CheckFile, Keys, Last))
        {
            Out = Keys.front().second;
            return true;
        }
    Error = Last;
    return false;
}

void ForgetFoundKeys()
{
    std::lock_guard G(Lock);
    Found.clear();
}

bool GetKey(const Context& Ctx, std::string_view Id, const std::filesystem::path& File, std::vector<uint8_t>& Out, std::string& Error)
{
    Out.clear();
    const KeyProvider* Provider = Ctx.Keys != nullptr ? Ctx.Keys : DefaultContext().Keys;
    if (Provider != nullptr && Provider->Key(Id, Out) && !Out.empty()) return true;
    Out.clear();

    const KeySpec* S = Spec(Id);
    if (S == nullptr)
    {
        Error = std::format("the key '{}' is not available (no key provider gives it)", Id);
        return false;
    }
    const KeyOptions& O = Ctx.KeySearch;
    const auto Fail = [&](const std::string& Why) {
        Error = std::format("the {} key '{}' is not available: {}", S->Game, Id, Why);
        return false;
    };

    std::lock_guard G(Lock);
    // Where it comes from: a URL, or the exes of the install
    std::vector<Stamp> Sources;
    std::filesystem::path Install;
    if (S->Exes.empty())
        Sources.push_back(Stamp{ S2KeyUrl });
    else
    {
        Install = FindKeyInstall(Id, Ctx.Install.empty() ? File : Ctx.Install);
        if (Install.empty())
            return Fail(std::format("no {} in {} or a folder above it (give the game's folder: Context::Install, or a KeyProvider)",
                                    ExeList(*S), (Ctx.Install.empty() ? File : Ctx.Install).string()));
        for (const auto* Exe : S->Exes)
            if (const auto St = FileStamp(Install / Exe)) Sources.push_back(*St);
    }

    for (const auto& From : Sources)
        if (const Entry* E = Lookup(Found, Id, From))
        {
            Out = E->Key;
            return true;
        }
    if (O.UseCache)
    {
        const auto Cached = ReadCache(CacheFileOf(O));
        for (const auto& From : Sources)
            if (const Entry* E = Lookup(Cached, Id, From); E && (S->Exes.size() || Known(*S, E->Key)))
            {
                Out = E->Key;
                Remember(Found, *E);
                return true;
            }
    }

    if (S->Exes.empty() && !O.Network)
        return Fail("it is not in the game's files, and fetching it from Scobalula/s2_ff_killer is turned off "
                    "(KeyOptions::Network): turn it on, or give the key with a KeyProvider");
    if (!S->Exes.empty() && !O.FindInGameFiles)
        return Fail("looking for it in the game's files is turned off (KeyOptions::FindInGameFiles)");

    std::string Why;
    for (const auto& From : Sources)
    {
        std::vector<std::pair<std::string, Bytes>> Keys;
        const std::filesystem::path Exe = S->Exes.empty() ? std::filesystem::path() : std::filesystem::path(From.Source);
        const auto CheckFile = IsFile(File) && File.extension() == ".ff" ? File : std::filesystem::path();
        if (!FindFrom(*S, Exe, Install, CheckFile, Keys, Why)) continue;
        std::vector<Entry> New;
        for (auto& [KeyId, K] : Keys) New.push_back(Entry{ KeyId, From, std::move(K) });
        for (const auto& E : New) Remember(Found, E);
        if (O.UseCache) WriteCache(CacheFileOf(O), New);
        Out = New.front().Key;
        return true;
    }
    return Fail(Why.empty() ? "not found" : Why);
}
}
