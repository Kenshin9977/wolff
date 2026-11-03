#pragma once

// What a container needs besides its file: decryption keys and an Oodle decompressor.
// Wolff carries no key: it finds each one in the game's own files (WWII's, which is not there, it
// fetches from where it was published) the first time a container asks, and caches it (Keys.h).
// A caller's KeyProvider, when there is one, is asked first. Oodle cannot be redistributed: the
// context's OodleProvider decodes Oodle blocks (OodleDllLoader loads the games' own DLLs).

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace wolff
{
    // The key ids a built-in container asks for
    namespace keys
    {
        // Black Ops 2's fast file stream cipher: the 32-byte Salsa20 key ("TAff0100", "TAffu100")
        inline constexpr std::string_view T6Salsa20 = "t6_salsa20";
        // WWII's signed fast files: the RSA private key (PKCS#1 DER) the AES key is sealed with
        inline constexpr std::string_view S2RsaPrivate = "s2_rsa_private";
        // Call of Duty Online's fast files: the RSA private key (PKCS#1 DER) of their seal
        inline constexpr std::string_view CodolRsa = "codol_rsa";
        // Call of Duty Online's other archived files (images, sounds): their 24-byte AES-192 key
        inline constexpr std::string_view CodolFileAes = "codol_file_aes";
    }

    // Resolves a key by id: an optional override, asked before Wolff looks for the key itself
    class KeyProvider
    {
    public:
        virtual ~KeyProvider() = default;
        // The key named Id into Out; false when this provider has none
        virtual bool Key(std::string_view Id, std::vector<uint8_t>& Out) const = 0;
    };

    // A KeyProvider over a function
    class CallbackKeyProvider final : public KeyProvider
    {
    public:
        using Callback = std::function<bool(std::string_view Id, std::vector<uint8_t>& Out)>;
        explicit CallbackKeyProvider(Callback Get) : Get(std::move(Get)) {}
        bool Key(std::string_view Id, std::vector<uint8_t>& Out) const override { return Get && Get(Id, Out); }

    private:
        Callback Get;
    };

    // One Oodle library's decoder. Decompress is called from several threads at once.
    class OodleDecompressor
    {
    public:
        virtual ~OodleDecompressor() = default;
        // One Oodle block of InSize bytes into exactly OutSize: the bytes produced, 0 on failure
        virtual size_t Decompress(const uint8_t* In, size_t InSize, uint8_t* Out, size_t OutSize) const = 0;
    };

    // Gives the decoder of an Oodle library by its DLL name ("oo2core_6_win64.dll" for Black Ops 4,
    // "oo2core_8_win64.dll" for Cold War and the IWffa100 titles, "oo2core_7_win64.dll"): each name
    // its own decoder, never one process-wide slot.
    class OodleProvider
    {
    public:
        virtual ~OodleProvider() = default;
        // nullptr when that library is not available
        virtual const OodleDecompressor* Find(std::string_view Library) = 0;
    };

    // The default OodleProvider: loads the named DLL at run time, the system's search first (the
    // exe's folder), then each search directory and up to three of its parents (a game's install
    // given as its zone folder). One slot per DLL name, loaded once and kept; a library not found
    // is looked for again on the next Find (a search directory may have been added since).
    class OodleDllLoader final : public OodleProvider
    {
    public:
        OodleDllLoader();
        explicit OodleDllLoader(std::vector<std::filesystem::path> SearchDirs);
        ~OodleDllLoader() override;
        OodleDllLoader(const OodleDllLoader&) = delete;
        OodleDllLoader& operator=(const OodleDllLoader&) = delete;

        void AddSearchDir(const std::filesystem::path& Dir);
        const OodleDecompressor* Find(std::string_view Library) override;

    private:
        struct Library;
        std::mutex Lock;
        std::vector<std::filesystem::path> Dirs;
        std::vector<std::unique_ptr<Library>> Loaded;
    };

    // How Wolff gets a key no KeyProvider gave
    struct KeyOptions
    {
        // Look for the key in the game's files (Black Ops 2's and Call of Duty Online's exe)
        bool FindInGameFiles = true;
        // WWII's key is not in its files: fetched once from Scobalula/s2_ff_killer (a pinned commit,
        // the bytes checked against their SHA-256). False: no network access, a clear error instead.
        bool Network = true;
        // Keep found keys between runs (keyed by the exe's path, size and last write time)
        bool UseCache = true;
        // The cache file; empty: %LOCALAPPDATA%\wolff\keys.json
        std::filesystem::path CacheFile;
    };

    // What a container is given besides its file
    struct Context
    {
        const KeyProvider* Keys = nullptr;   // asked first; nullptr: the default context's (if any)
        OodleProvider* Oodle = nullptr;      // nullptr: the default context's OodleDllLoader
        // The game's folder (the one holding its exe); empty: found from the file being read, its
        // folder or one above it
        std::filesystem::path Install;
        KeyOptions KeySearch;
    };

    // The context the calls that take none use. Set once at start (not owned: the provider objects
    // must outlive every call); unset, it finds the keys itself and has an OodleDllLoader with no
    // search directory.
    const Context& DefaultContext();
    void SetDefaultContext(const Context& C);

    // Ctx's key Id into Out: Ctx's KeyProvider (else the default context's), then the cache, then
    // the game's files (Ctx.KeySearch). File is what is being read (a fast file, an archive, or the
    // install folder): the install is Ctx.Install, else File's folder or the first one above it
    // holding the game's exe. False with Error (never the key's bytes) when no source gives it.
    bool GetKey(const Context& Ctx, std::string_view Id, const std::filesystem::path& File, std::vector<uint8_t>& Out,
                std::string& Error);

    // Ctx's decoder for Library (the default loader when Ctx names no provider); nullptr with Error
    // when it is not available. Title names what needs it, for the error.
    const OodleDecompressor* GetOodle(const Context& Ctx, std::string_view Library, std::string_view Title, std::string& Error);
}
