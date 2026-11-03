#pragma once

// Call of Duty Online: its fast files ("IWff0100", version 461: IW4's authenticated stream, sealed),
// the Tencent .ifs archives they ship in, and the game's own layer over the other archived files.
// Formats as the game's code reads them (codoMP_client_shipRetail.exe; the file layer also as
// dtzxporter's WraithXOL, MIT, has it). Keys from the context: keys::CodolRsa, keys::CodolFileAes.

#include <wolff/ByteView.h>
#include <wolff/Context.h>
#include <wolff/ZoneBytes.h>

#include <cstdint>
#include <filesystem>
#include <map>
#include <regex>
#include <string>
#include <vector>

namespace wolff
{
    // Tencent IIPS archives (`.ifs`, magic "nifs"), an MPQ v4 clone: HET/BET tables encrypted with
    // MPQ's block cipher, names hashed with Jenkins' hashlittle2 and listed by a "(listfile)". The
    // game files themselves are stored as they are; the listfile is sectored, encrypted and zlib'd.
    namespace Ifs
    {
        // The install's paths are Korean: kept as UTF-8 in a std::string, whatever the code page
        inline std::filesystem::path Utf8Path(const std::string& S)
        {
            return std::filesystem::path(std::u8string(S.begin(), S.end()));
        }
        inline std::string Utf8(const std::filesystem::path& P)
        {
            const std::u8string U = P.u8string();
            return std::string(U.begin(), U.end());
        }

        struct Entry
        {
            std::string Name;          // as the listfile spells it
            uint64_t Pos = 0;
            uint64_t Size = 0;
            uint64_t StoredSize = 0;
            uint32_t Flags = 0;
        };

        class Archive
        {
        public:
            bool Open(const std::string& FilePath, std::string& Error);
            const std::string& Path() const { return File; }
            // the named files, listfile and directories left out
            const std::vector<Entry>& Files() const { return Named; }
            bool Read(const Entry& E, std::vector<uint8_t>& Out, std::string& Error) const;

        private:
            bool Find(const std::string& Name, Entry& Out) const;

            std::string File;
            uint32_t HeaderSize = 0;
            uint32_t SectorSize = 0;
            uint64_t AndMask = 0, OrMask = 0;
            std::map<uint64_t, Entry> ByHash;
            std::vector<Entry> Named;
        };

        // Every archive of an install (<install>\IIPS\IIPSDownload\*.ifs), each file at its latest
        // version: a patch archive <stem>_V<n>.<k>.ifs replaces the files of <stem>_V<n>.ifs.
        class Install
        {
        public:
            bool Open(const std::string& InstallDir, std::string& Error);
            struct Located
            {
                size_t Archive = 0;
                Entry File;
                std::vector<uint32_t> Version;
            };
            // keyed by the lower-case path with '/' separators ("client_shipretail/chinese/x.ff")
            const std::map<std::string, Located>& Files() const { return Latest; }
            const Located* Find(const std::string& Key) const;
            bool Read(const Located& L, std::vector<uint8_t>& Out, std::string& Error) const;
            size_t ArchiveCount() const { return Archives.size(); }
            // the install folder Open was given
            const std::string& Folder() const { return Root; }
            // the install folder an input names: the folder itself, or one holding IIPS\IIPSDownload
            static std::string ArchiveFolder(const std::string& InstallDir);
            static std::string Key(const std::string& Name);

        private:
            std::vector<Archive> Archives;
            std::map<std::string, Located> Latest;
            std::string Root;
        };

        // A file name pattern ('*' any run, '?' one character), case ignored
        std::regex GlobRegex(const std::string& Glob);
    }

    namespace Codol
    {
        // A sealed fast file decrypted and inflated. After the 21-byte header, 0x100 bytes RSA-2048
        // (PKCS#1 v1.5) seal 40 bytes: an AES-192 key and a counter. Then 0x2000-byte blocks in
        // AES-192 counter mode (tomcrypt's little-endian counter): block 0 is the IWffs100 header
        // (counter from the seal), then groups of one hash block (counter: the header's hash g at
        // +0x130 + 32 g) and up to 256 data blocks (counter: the hash block's entry k). A counter is
        // the first 16 bytes of its block's SHA-256, checked here. The data blocks are one zlib
        // stream: the zone. The game's code: COL_DB_LoadXFile 0x483db0, its block read 0x4834f0.
        bool DecryptFastFile(ByteView File, ZoneBytes& Zone, std::string& Error, const Context& Ctx = DefaultContext(),
                             const std::filesystem::path& From = {});

        // The game's own layer over the files of its .ifs archives (images, sounds, model data; not
        // the fast files): zlib, then AES-192 in counter mode (tomcrypt's big-endian counter) per
        // 0x8000-byte block, the block's counter {nonce, unpacked size, block offset, block size},
        // the nonce a CRC-32 of the file's base name seeded with its length; the unpacked size
        // follows the data (u32). The game's code: 0x76ab00 (key), 0x76abc0 (nonce), 0x76ac80 (a block).
        // Data unwrapped in place when it is wrapped; false (Data untouched) when it is not or when
        // the key is not available.
        bool UnwrapFile(const std::string& Name, std::vector<uint8_t>& Data, const Context& Ctx = DefaultContext(),
                        const std::filesystem::path& From = {});

        // (DecryptFastFile, UnwrapFile: From is the file or archive the data was read from, or the
        // install folder (Ifs::Install::Folder), where the keys are found; Ctx.Install also gives it.)

        // The zone of <Folder>/<Name>.ff read out of an install's archives and decrypted
        bool ReadZone(const Ifs::Install& Archives, const std::string& Folder, const std::string& Name, ZoneBytes& Zone, std::string& Error,
                      const Context& Ctx = DefaultContext());

        // Registers the sealed fast file container ("IWff0100", 461) (FastFile.h's RegisterBuiltins calls it)
        void RegisterBuiltins();
    }
}
