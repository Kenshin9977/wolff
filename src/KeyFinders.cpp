// The keys read out of the games' own files (Keys.h). Each finder is structural: it follows what
// the game's code does with the key, no address of one build. Never log a key's bytes.

#include "KeyFinders.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <winhttp.h>

#include <Zydis/Zydis.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <fstream>
#include <map>
#include <optional>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "winhttp.lib")

namespace wolff::keyfind
{
namespace
{
    bool ReadFile(const std::filesystem::path& Path, Bytes& Out, std::string& Error)
    {
        std::ifstream F(Path, std::ios::binary);
        if (!F)
        {
            Error = "could not open " + Path.filename().string();
            return false;
        }
        F.seekg(0, std::ios::end);
        Out.resize((size_t)F.tellg());
        F.seekg(0);
        F.read(reinterpret_cast<char*>(Out.data()), (std::streamsize)Out.size());
        if (!F)
        {
            Error = "could not read " + Path.filename().string();
            return false;
        }
        return true;
    }

    uint32_t U32(const Bytes& D, size_t At) { uint32_t V; std::memcpy(&V, D.data() + At, 4); return V; }
    uint16_t U16(const Bytes& D, size_t At) { uint16_t V; std::memcpy(&V, D.data() + At, 2); return V; }
    uint64_t U64(const uint8_t* P) { uint64_t V; std::memcpy(&V, P, 8); return V; }

    // ------------------------------------------------------------------ PE
    struct Section
    {
        char Name[9] = {};
        uint32_t VirtualAddress = 0, VirtualSize = 0, RawOffset = 0, RawSize = 0, Flags = 0;
    };
    struct Pe
    {
        uint64_t ImageBase = 0;
        uint32_t EntryPoint = 0;
        std::vector<Section> Sections;

        bool Parse(const Bytes& D)
        {
            if (D.size() < 0x40 || D[0] != 'M' || D[1] != 'Z') return false;
            const size_t At = U32(D, 0x3C);
            if (At + 24 > D.size() || std::memcmp(D.data() + At, "PE\0\0", 4) != 0) return false;
            const uint16_t Count = U16(D, At + 6), OptSize = U16(D, At + 20);
            const size_t Opt = At + 24;
            if (Opt + OptSize > D.size()) return false;
            const uint16_t Magic = U16(D, Opt);
            EntryPoint = U32(D, Opt + 16);
            ImageBase = Magic == 0x20b ? U64(D.data() + Opt + 24) : U32(D, Opt + 28);
            for (size_t K = 0; K < Count; K++)
            {
                const size_t S = Opt + OptSize + K * 40;
                if (S + 40 > D.size()) return false;
                Section X;
                std::memcpy(X.Name, D.data() + S, 8);
                X.VirtualSize = U32(D, S + 8);
                X.VirtualAddress = U32(D, S + 12);
                X.RawSize = U32(D, S + 16);
                X.RawOffset = U32(D, S + 20);
                X.Flags = U32(D, S + 36);
                if (X.RawOffset > D.size()) X.RawSize = 0;
                else X.RawSize = (uint32_t)std::min<size_t>(X.RawSize, D.size() - X.RawOffset);
                Sections.push_back(X);
            }
            return !Sections.empty();
        }
        std::optional<size_t> RvaToOffset(uint64_t Rva) const
        {
            for (const auto& S : Sections)
                if (Rva >= S.VirtualAddress && Rva < (uint64_t)S.VirtualAddress + std::max(S.VirtualSize, S.RawSize))
                {
                    const uint64_t O = Rva - S.VirtualAddress;
                    if (O < S.RawSize) return S.RawOffset + O;
                    return std::nullopt;
                }
            return std::nullopt;
        }
        std::optional<uint64_t> OffsetToVa(size_t Off) const
        {
            for (const auto& S : Sections)
                if (Off >= S.RawOffset && Off < (size_t)S.RawOffset + S.RawSize)
                    return ImageBase + S.VirtualAddress + (Off - S.RawOffset);
            return std::nullopt;
        }
        bool Has(const char* Name) const
        {
            for (const auto& S : Sections)
                if (std::strcmp(S.Name, Name) == 0) return true;
            return false;
        }
    };

    // ------------------------------------------------------------------ CNG helpers
    struct Alg
    {
        BCRYPT_ALG_HANDLE H = nullptr;
        explicit Alg(LPCWSTR Id) { if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&H, Id, nullptr, 0))) H = nullptr; }
        ~Alg() { if (H) BCryptCloseAlgorithmProvider(H, 0); }
        Alg(const Alg&) = delete;
        Alg& operator=(const Alg&) = delete;
    };
    struct Key
    {
        BCRYPT_KEY_HANDLE H = nullptr;
        Key() = default;
        ~Key() { if (H) BCryptDestroyKey(H); }
        Key(const Key&) = delete;
        Key& operator=(const Key&) = delete;
    };

    bool AesDecrypt(const uint8_t* KeyBytes, size_t KeySize, LPCWSTR Mode, uint8_t* Iv, uint8_t* Data, size_t Size)
    {
        Alg A(BCRYPT_AES_ALGORITHM);
        if (!A.H || !BCRYPT_SUCCESS(BCryptSetProperty(A.H, BCRYPT_CHAINING_MODE, (PUCHAR)Mode, (ULONG)((wcslen(Mode) + 1) * 2), 0)))
            return false;
        Key K;
        if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(A.H, &K.H, nullptr, 0, (PUCHAR)KeyBytes, (ULONG)KeySize, 0))) return false;
        ULONG Done = 0;
        return BCRYPT_SUCCESS(BCryptDecrypt(K.H, Data, (ULONG)Size, nullptr, Iv, Iv ? 16 : 0, Data, (ULONG)Size, &Done, 0));
    }

    // A PKCS#1 DER private key imported into CNG
    bool ImportRsa(const Alg& Rsa, const uint8_t* Der, size_t Size, Key& Out)
    {
        DWORD BlobSize = 0;
        BYTE* Blob = nullptr;
        if (!CryptDecodeObjectEx(X509_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY, Der, (DWORD)Size, CRYPT_DECODE_ALLOC_FLAG, nullptr, &Blob,
                                 &BlobSize))
            return false;
        const bool Ok = BCRYPT_SUCCESS(BCryptImportKeyPair(Rsa.H, nullptr, LEGACY_RSAPRIVATE_BLOB, &Out.H, Blob, BlobSize, 0));
        LocalFree(Blob);
        return Ok;
    }

    ULONG RsaBytes(const Key& K)
    {
        DWORD Bits = 0;
        ULONG Got = 0;
        BCryptGetProperty(K.H, BCRYPT_KEY_LENGTH, (PUCHAR)&Bits, sizeof(Bits), &Got, 0);
        return (Bits + 7) / 8;
    }

    // The public half encrypts, the private half (its primes) decrypts back: they belong together
    bool RoundTrips(const Key& K)
    {
        const ULONG N = RsaBytes(K);
        if (N < 128) return false;
        Bytes In(N), Mid(N), Back(N);
        for (ULONG I = 2; I < N; I++) In[I] = (uint8_t)(I * 37 + 11);
        In[1] = 2;
        ULONG Done = 0;
        return BCRYPT_SUCCESS(BCryptEncrypt(K.H, In.data(), N, nullptr, nullptr, 0, Mid.data(), N, &Done, BCRYPT_PAD_NONE)) &&
               BCRYPT_SUCCESS(BCryptDecrypt(K.H, Mid.data(), N, nullptr, nullptr, 0, Back.data(), N, &Done, BCRYPT_PAD_NONE)) &&
               In == Back;
    }

    // ------------------------------------------------------------------ DER
    bool DerLength(const Bytes& B, size_t& I, size_t& Len)
    {
        if (I >= B.size()) return false;
        size_t L = B[I++];
        if (L & 0x80)
        {
            const size_t K = L & 0x7F;
            if (K == 0 || K > 4 || I + K > B.size()) return false;
            L = 0;
            for (size_t J = 0; J < K; J++) L = (L << 8) | B[I++];
        }
        Len = L;
        return true;
    }

    // A PKCS#1 RSAPrivateKey (SEQUENCE of nine INTEGERs, version 0) at At: its size
    size_t RsaPrivateKeyAt(const Bytes& B, size_t At)
    {
        if (At >= B.size() || B[At] != 0x30) return 0;
        size_t I = At + 1, Len = 0;
        if (!DerLength(B, I, Len) || I + Len > B.size()) return 0;
        const size_t End = I + Len;
        int Ints = 0;
        while (I < End && Ints < 9)
        {
            if (B[I] != 0x02) return 0;
            size_t J = I + 1, L2 = 0;
            if (!DerLength(B, J, L2) || J + L2 > End) return 0;
            if (Ints == 0 && !(L2 == 1 && B[J] == 0)) return 0;
            if (Ints == 1 && L2 < 128) return 0;   // a modulus of 1024 bits at least
            I = J + L2;
            Ints++;
        }
        return Ints == 9 && I == End ? End - At : 0;
    }

    // ------------------------------------------------------------------ SteamStub 3.1 (x86)
    // After Steamless (atom0s), Variant31.x86: the header (0xF0 bytes before the entry point) under a
    // rolling XOR, the code section AES-256-CBC with its first 16 bytes kept in the header.
    constexpr size_t StubHeaderSize = 0xF0;
    constexpr uint32_t StubSignature = 0xC0DEC0DF;

    bool UnwrapSteamStub31(Bytes& D, const Pe& P, std::string& Error)
    {
        const auto Ep = P.RvaToOffset(P.EntryPoint);
        if (!Ep || *Ep < StubHeaderSize)
        {
            Error = "SteamStub: no header before the entry point";
            return false;
        }
        uint8_t H[StubHeaderSize];
        std::memcpy(H, D.data() + *Ep - StubHeaderSize, StubHeaderSize);
        uint32_t XorKey;
        std::memcpy(&XorKey, H, 4);
        for (size_t At = 4; At + 4 <= StubHeaderSize; At += 4)
        {
            uint32_t V;
            std::memcpy(&V, H + At, 4);
            const uint32_t Plain = V ^ XorKey;
            std::memcpy(H + At, &Plain, 4);
            XorKey = V;
        }
        uint32_t Signature, Flags;
        std::memcpy(&Signature, H + 4, 4);
        std::memcpy(&Flags, H + 0x3C, 4);
        if (Signature != StubSignature)
        {
            Error = "SteamStub: not variant 3.1 x86";
            return false;
        }
        if (Flags & 4) return true;   // NoEncryption
        const uint64_t CodeRva = U64(H + 0x48), CodeRaw = U64(H + 0x50);
        const Section* Code = nullptr;
        for (const auto& S : P.Sections)
            if (S.VirtualAddress == CodeRva) Code = &S;
        if (Code == nullptr || CodeRaw > Code->RawSize || Code->RawOffset + CodeRaw > D.size())
        {
            Error = "SteamStub: the code section it names is not there";
            return false;
        }
        uint8_t AesKey[32], Iv[16];
        std::memcpy(AesKey, H + 0x58, 32);
        std::memcpy(Iv, H + 0x78, 16);
        if (!AesDecrypt(AesKey, 32, BCRYPT_CHAIN_MODE_ECB, nullptr, Iv, 16))
        {
            Error = "SteamStub: could not decrypt the IV";
            return false;
        }
        Bytes Enc(H + 0x88, H + 0x98);
        Enc.insert(Enc.end(), D.begin() + Code->RawOffset, D.begin() + Code->RawOffset + (size_t)CodeRaw);
        Enc.resize(Enc.size() / 16 * 16);
        if (!AesDecrypt(AesKey, 32, BCRYPT_CHAIN_MODE_CBC, Iv, Enc.data(), Enc.size()))
        {
            Error = "SteamStub: could not decrypt the code section";
            return false;
        }
        std::memcpy(D.data() + Code->RawOffset, Enc.data(), std::min<size_t>(Enc.size(), Code->RawSize));
        return true;
    }

    // ------------------------------------------------------------------ Black Ops 2's key
    // 1. "expand 32-byte k" (Salsa20's constant) -> `mov r32, <it>` in the key setup function;
    // 2. its call after `push 0x100 ... push G` -> G, the key global; 3. the function storing to G
    // (DB_SetKey); 4. in DB_SetKey's caller, the 32 bytes stored as immediates to the stack buffer
    // pushed before the call (a linear sweep keeping track of esp).
    struct Text
    {
        uint64_t Va = 0;
        const uint8_t* P = nullptr;
        size_t Size = 0;
        bool Contains(uint64_t V) const { return V >= Va && V < Va + Size; }
    };

    std::optional<uint64_t> FunctionStart(const Text& T, uint64_t Va, size_t MaxBack = 0x4000)
    {
        if (!T.Contains(Va)) return std::nullopt;
        const size_t I = (size_t)(Va - T.Va);
        const size_t Low = I > MaxBack ? I - MaxBack : 1;
        for (size_t K = I; K > Low; K--)
            if (T.P[K - 1] == 0xCC && T.P[K] != 0xCC) return T.Va + K;
        return std::nullopt;
    }

    std::vector<uint64_t> CallsTo(const Text& T, uint64_t Target)
    {
        std::vector<uint64_t> Out;
        for (size_t I = 0; I + 5 <= T.Size; I++)
        {
            if (T.P[I] != 0xE8) continue;
            int32_t Rel;
            std::memcpy(&Rel, T.P + I + 1, 4);
            if ((int64_t)(T.Va + I + 5) + Rel == (int64_t)Target) Out.push_back(T.Va + I);
        }
        return Out;
    }

    std::vector<size_t> FindAll(const uint8_t* P, size_t Size, const uint8_t* Needle, size_t N)
    {
        std::vector<size_t> Out;
        if (Size < N) return Out;
        for (const uint8_t* At = P; (At = std::search(At, P + Size, Needle, Needle + N)) != P + Size; At++)
            Out.push_back((size_t)(At - P));
        return Out;
    }

    // The bytes stored as immediates to the stack before Call, at the buffer last pushed (lea r,
    // [esp+d] then push r): 32 of them, all stored, or nothing
    std::optional<Bytes> StackKey(const Text& T, uint64_t Start, uint64_t Call)
    {
        if (!T.Contains(Start) || !T.Contains(Call) || Call < Start) return std::nullopt;
        ZydisDecoder Dec;
        ZydisDecoderInit(&Dec, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);
        int64_t Sp = 0;
        std::map<int64_t, uint8_t> Mem;
        std::map<ZydisRegister, int64_t> LeaOfReg;
        std::optional<int64_t> LastPush;
        const size_t End = (size_t)(Call - T.Va) + 5;
        for (size_t I = (size_t)(Start - T.Va); I < End;)
        {
            if (T.Va + I == Call) break;
            ZydisDecodedInstruction Ins;
            ZydisDecodedOperand Ops[ZYDIS_MAX_OPERAND_COUNT];
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&Dec, T.P + I, End - I, &Ins, Ops))) break;
            I += Ins.length;
            const auto M = Ins.mnemonic;
            const bool HasOp = Ins.operand_count_visible > 0;
            const bool StackMem0 = HasOp && Ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY && Ops[0].mem.base == ZYDIS_REGISTER_ESP &&
                                   Ops[0].mem.index == ZYDIS_REGISTER_NONE;
            if (M == ZYDIS_MNEMONIC_PUSH)
            {
                Sp -= 4;
                if (HasOp && Ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER && LeaOfReg.count(Ops[0].reg.value))
                    LastPush = LeaOfReg[Ops[0].reg.value];
                else
                    LastPush.reset();
            }
            else if (M == ZYDIS_MNEMONIC_POP)
                Sp += 4;
            else if ((M == ZYDIS_MNEMONIC_SUB || M == ZYDIS_MNEMONIC_ADD) && Ins.operand_count_visible >= 2 &&
                     Ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER && Ops[0].reg.value == ZYDIS_REGISTER_ESP &&
                     Ops[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                Sp += M == ZYDIS_MNEMONIC_SUB ? -Ops[1].imm.value.s : Ops[1].imm.value.s;
            else if (M == ZYDIS_MNEMONIC_LEA && Ins.operand_count_visible >= 2 && Ops[1].type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                if (Ops[1].mem.base == ZYDIS_REGISTER_ESP && Ops[1].mem.index == ZYDIS_REGISTER_NONE)
                    LeaOfReg[Ops[0].reg.value] = Sp + Ops[1].mem.disp.value;
                else
                    LeaOfReg.erase(Ops[0].reg.value);
            }
            else if (M == ZYDIS_MNEMONIC_MOV && StackMem0 && Ins.operand_count_visible >= 2 &&
                     Ops[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
            {
                const int64_t A = Sp + Ops[0].mem.disp.value;
                const uint64_t V = Ops[1].imm.value.u;
                for (int K = 0; K < Ops[0].size / 8; K++) Mem[A + K] = (uint8_t)(V >> (8 * K));
            }
            else if (M == ZYDIS_MNEMONIC_RET)
                break;
            if (M != ZYDIS_MNEMONIC_PUSH && M != ZYDIS_MNEMONIC_LEA && HasOp && Ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
                LeaOfReg.erase(Ops[0].reg.value);
        }
        if (!LastPush) return std::nullopt;
        Bytes K(32);
        for (int64_t I = 0; I < 32; I++)
        {
            const auto It = Mem.find(*LastPush + I);
            if (It == Mem.end()) return std::nullopt;
            K[(size_t)I] = It->second;
        }
        return K;
    }

    // The key global G in `push 0x100 ; ... ; push G` in the 0x20 bytes before a call
    std::optional<uint32_t> KeyGlobalBefore(const Text& T, uint64_t Call)
    {
        const size_t C = (size_t)(Call - T.Va);
        if (C < 0x20) return std::nullopt;
        const uint8_t* Pre = T.P + C - 0x20;
        static const uint8_t Push100[] = { 0x68, 0x00, 0x01, 0x00, 0x00 };
        for (size_t I = 0; I + 5 <= 0x20; I++)
        {
            if (std::memcmp(Pre + I, Push100, 5) != 0) continue;
            for (int Gap = 8; Gap >= 0; Gap--)
            {
                const size_t J = I + 5 + Gap;
                if (J + 5 <= 0x20 && Pre[J] == 0x68)
                {
                    uint32_t G;
                    std::memcpy(&G, Pre + J + 1, 4);
                    return G;
                }
            }
        }
        return std::nullopt;
    }

    // A store to the absolute address whose 4 bytes start at W (movq/movups/movaps/movdqa/movdqu/mov)
    bool StoreTo(const Text& T, size_t W)
    {
        if (W < 4) return false;
        const uint8_t* P = T.P + W - 4;
        const auto Ends = [&](std::initializer_list<uint8_t> S) { return std::equal(S.begin(), S.end(), P + 4 - S.size()); };
        return Ends({ 0x66, 0x0F, 0xD6, 0x05 }) || P[2] == 0x89 || (P[1] == 0x0F && (P[2] == 0x11 || P[2] == 0x29)) ||
               Ends({ 0xF3, 0x0F, 0x7F, 0x05 }) || Ends({ 0x66, 0x0F, 0x7F, 0x05 });
    }

    void LocateT6Key(const Bytes& D, const Pe& P, const Text& T, std::vector<Bytes>& Found)
    {
        static const char Sigma[] = "expand 32-byte k";
        const auto SigmaAt = FindAll(D.data(), D.size(), (const uint8_t*)Sigma, 16);
        if (SigmaAt.empty()) return;
        const auto S = P.OffsetToVa(SigmaAt.front());
        if (!S) return;
        const uint32_t S32 = (uint32_t)*S;
        for (const size_t Ref : FindAll(T.P, T.Size, (const uint8_t*)&S32, 4))
        {
            if (Ref == 0 || T.P[Ref - 1] < 0xB8 || T.P[Ref - 1] > 0xBF) continue;   // mov r32, imm32
            const auto Setup = FunctionStart(T, T.Va + Ref);
            if (!Setup) continue;
            for (const uint64_t C : CallsTo(T, *Setup))
            {
                const auto G = KeyGlobalBefore(T, C);
                if (!G) continue;
                const auto Caller = FunctionStart(T, C);
                for (const size_t W : FindAll(T.P, T.Size, (const uint8_t*)&*G, 4))
                {
                    if (!StoreTo(T, W)) continue;
                    const auto SetKey = FunctionStart(T, T.Va + W);
                    if (!SetKey || SetKey == Caller) continue;
                    for (const uint64_t C2 : CallsTo(T, *SetKey))
                        if (const auto Builder = FunctionStart(T, C2))
                            if (auto K = StackKey(T, *Builder, C2)) Found.push_back(std::move(*K));
                    break;   // the first function storing to G is DB_SetKey
                }
            }
        }
    }

    // ------------------------------------------------------------------ HTTPS
    bool HttpsGet(const std::wstring& Url, std::string& Body, std::string& Error)
    {
        URL_COMPONENTS U = {};
        U.dwStructSize = sizeof(U);
        wchar_t Host[256] = {}, Path[1024] = {};
        U.lpszHostName = Host;
        U.dwHostNameLength = 256;
        U.lpszUrlPath = Path;
        U.dwUrlPathLength = 1024;
        if (!WinHttpCrackUrl(Url.c_str(), 0, 0, &U) || U.nScheme != INTERNET_SCHEME_HTTPS)
        {
            Error = "not an https URL";
            return false;
        }
        struct Handle
        {
            HINTERNET H;
            ~Handle() { if (H) WinHttpCloseHandle(H); }
        };
        Handle Session{ WinHttpOpen(L"wolff", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0) };
        if (!Session.H) Session.H = WinHttpOpen(L"wolff", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!Session.H)
        {
            Error = "could not start WinHTTP";
            return false;
        }
        WinHttpSetTimeouts(Session.H, 10000, 10000, 15000, 15000);
        Handle Connect{ WinHttpConnect(Session.H, Host, U.nPort, 0) };
        Handle Request{ Connect.H ? WinHttpOpenRequest(Connect.H, L"GET", Path, nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                                       WINHTTP_FLAG_SECURE)
                                  : nullptr };
        if (!Request.H || !WinHttpSendRequest(Request.H, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
            !WinHttpReceiveResponse(Request.H, nullptr))
        {
            Error = "could not reach the host (error " + std::to_string(GetLastError()) + ")";
            return false;
        }
        DWORD Status = 0, Size = sizeof(Status);
        WinHttpQueryHeaders(Request.H, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &Status, &Size,
                            WINHTTP_NO_HEADER_INDEX);
        if (Status != 200)
        {
            Error = "the host answered HTTP " + std::to_string(Status);
            return false;
        }
        Body.clear();
        for (;;)
        {
            DWORD Avail = 0;
            if (!WinHttpQueryDataAvailable(Request.H, &Avail))
            {
                Error = "the download broke off";
                return false;
            }
            if (Avail == 0) break;
            const size_t Old = Body.size();
            Body.resize(Old + Avail);
            DWORD Read = 0;
            if (!WinHttpReadData(Request.H, Body.data() + Old, Avail, &Read))
            {
                Error = "the download broke off";
                return false;
            }
            Body.resize(Old + Read);
            if (Body.size() > (1 << 20))
            {
                Error = "the file is far larger than a key";
                return false;
            }
        }
        return true;
    }
}

std::string Sha256Hex(const uint8_t* Data, size_t Size)
{
    uint8_t Digest[32] = {};
    BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0, (PUCHAR)Data, (ULONG)Size, Digest, 32);
    static const char* Hex = "0123456789abcdef";
    std::string Out;
    for (const uint8_t B : Digest)
    {
        Out += Hex[B >> 4];
        Out += Hex[B & 15];
    }
    return Out;
}

bool RsaKeyPairAgrees(const Bytes& Der)
{
    Alg Rsa(BCRYPT_RSA_ALGORITHM);
    Key K;
    return Rsa.H && ImportRsa(Rsa, Der.data(), Der.size(), K) && RoundTrips(K);
}

bool T6FromExe(const std::filesystem::path& Exe, std::vector<Bytes>& Candidates, std::string& Error)
{
    Bytes D;
    if (!ReadFile(Exe, D, Error)) return false;
    Pe P;
    if (!P.Parse(D))
    {
        Error = Exe.filename().string() + " is not a PE file";
        return false;
    }
    if (P.Has(".bind") && !UnwrapSteamStub31(D, P, Error)) return false;
    const Section& Code = P.Sections.front();
    const Text T{ P.ImageBase + Code.VirtualAddress, D.data() + Code.RawOffset, std::min(Code.VirtualSize, Code.RawSize) };
    const size_t Before = Candidates.size();
    LocateT6Key(D, P, T, Candidates);
    if (Candidates.size() == Before)
    {
        Error = "no key built before DB_SetKey in " + Exe.filename().string();
        return false;
    }
    return true;
}

bool CodolFromExe(const std::filesystem::path& Exe, Bytes& RsaDer, Bytes& FileKey, std::string& Error)
{
    RsaDer.clear();
    FileKey.clear();
    Bytes D;
    if (!ReadFile(Exe, D, Error)) return false;
    Pe P;
    if (!P.Parse(D))
    {
        Error = Exe.filename().string() + " is not a PE file";
        return false;
    }
    Alg Rsa(BCRYPT_RSA_ALGORITHM);
    if (!Rsa.H)
    {
        Error = "could not open CNG's RSA";
        return false;
    }
    // The PKCS#1 private key: SEQUENCE, then INTEGER 0, then a long INTEGER (the modulus)
    static const uint8_t Shape[] = { 0x02, 0x01, 0x00, 0x02, 0x82 };
    Key K;
    size_t KeyAt = 0;
    for (const size_t At : FindAll(D.data(), D.size(), Shape, sizeof(Shape)))
    {
        for (const size_t Hdr : { 4, 3 })
        {
            if (At < Hdr) continue;
            const size_t Size = RsaPrivateKeyAt(D, At - Hdr);
            if (Size == 0) continue;
            Key Candidate;
            if (!ImportRsa(Rsa, D.data() + At - Hdr, Size, Candidate) || !RoundTrips(Candidate)) continue;
            RsaDer.assign(D.begin() + (At - Hdr), D.begin() + (At - Hdr) + Size);
            std::swap(K.H, Candidate.H);
            KeyAt = At - Hdr;
            break;
        }
        if (!RsaDer.empty()) break;
    }
    if (RsaDer.empty())
    {
        Error = "no RSA private key in " + Exe.filename().string();
        return false;
    }

    // The file key: an RSA-OAEP (SHA-256, no label) seal opening to 24 bytes, 4-byte aligned, in a
    // section that is not code (the protector leaves those plain); the windows nearest the key
    // first, random-looking ones only (OAEP's label hash checks the rest)
    const ULONG N = RsaBytes(K);
    std::vector<const Section*> Data;
    for (const auto& S : P.Sections)
        if (!(S.Flags & IMAGE_SCN_CNT_CODE) && S.RawSize >= N) Data.push_back(&S);
    std::stable_sort(Data.begin(), Data.end(), [&](const Section* A, const Section* B) {
        const auto In = [&](const Section* S) { return KeyAt >= S->RawOffset && KeyAt < (size_t)S->RawOffset + S->RawSize; };
        return In(A) && !In(B);
    });
    BCRYPT_OAEP_PADDING_INFO Oaep = { BCRYPT_SHA256_ALGORITHM, nullptr, 0 };
    for (const Section* S : Data)
    {
        const size_t Raw = S->RawOffset, Size = S->RawSize;
        const size_t Centre = KeyAt >= Raw && KeyAt < Raw + Size ? KeyAt : Raw;
        std::vector<size_t> Offsets;
        for (size_t O = Raw + (Centre - Raw) % 4; O + N <= Raw + Size; O += 4) Offsets.push_back(O);
        std::stable_sort(Offsets.begin(), Offsets.end(), [&](size_t A, size_t B) {
            return (A > Centre ? A - Centre : Centre - A) < (B > Centre ? B - Centre : Centre - B);
        });
        for (const size_t O : Offsets)
        {
            std::array<bool, 256> Seen{};
            int Distinct = 0;
            for (size_t I = 0; I < N; I++)
                if (!Seen[D[O + I]]) Seen[D[O + I]] = true, Distinct++;
            if (Distinct < 140) continue;   // random bytes: ~162 distinct in 256
            uint8_t Out[512];
            ULONG Got = 0;
            if (BCRYPT_SUCCESS(BCryptDecrypt(K.H, D.data() + O, N, &Oaep, nullptr, 0, Out, sizeof(Out), &Got, BCRYPT_PAD_OAEP)) && Got == 24)
            {
                FileKey.assign(Out, Out + 24);
                SecureZeroMemory(Out, sizeof(Out));
                return true;
            }
        }
    }
    return true;
}

bool S2FromUrl(const std::wstring& Url, Bytes& RsaDer, std::string& Error)
{
    std::string Body;
    if (!HttpsGet(Url, Body, Error)) return false;
    // unsigned char RSAKey[1191] = { 0x30, 0x82, ... };
    const size_t Open = Body.find('{'), Close = Body.rfind('}');
    if (Open == std::string::npos || Close == std::string::npos || Close < Open)
    {
        Error = "the downloaded Key.h holds no byte array";
        return false;
    }
    RsaDer.clear();
    for (size_t I = Open + 1; I < Close; I++)
    {
        if (Body[I] != '0' || I + 2 >= Close || (Body[I + 1] != 'x' && Body[I + 1] != 'X')) continue;
        size_t J = I + 2;
        unsigned V = 0;
        int Digits = 0;
        while (J < Close && Digits < 3 && std::isxdigit((unsigned char)Body[J]))
        {
            const char C = (char)std::tolower((unsigned char)Body[J]);
            V = V * 16 + (unsigned)(C <= '9' ? C - '0' : C - 'a' + 10);
            J++, Digits++;
        }
        if (Digits == 0 || Digits > 2)
        {
            Error = "the downloaded Key.h is not a byte array";
            return false;
        }
        RsaDer.push_back((uint8_t)V);
        I = J - 1;
    }
    if (RsaDer.empty() || RsaPrivateKeyAt(RsaDer, 0) != RsaDer.size())
    {
        Error = "the downloaded Key.h does not hold a PKCS#1 private key";
        RsaDer.clear();
        return false;
    }
    return true;
}
}
