#include <wolff/WorldWar2.h>

#include "FastFileInternal.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <bcrypt.h>
#include <wincrypt.h>

#include <cstring>
#include <format>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

namespace wolff {

namespace
{
    // The RSA private key WWII fast files are sealed with comes from GetKey (keys::S2RsaPrivate: fetched once, Keys.h).

    constexpr size_t BlockSize = 16384;
    constexpr size_t MasterBlockSize = 16384;
    constexpr size_t SealedKeySize = 256;
    // 24 bytes of AES-192 key then 16 bytes of counter
    constexpr size_t UnsealedKeySize = 40;
    constexpr size_t AesKeySize = 24;
    constexpr size_t CounterSize = 16;
    // Where the master block's own run of counters starts
    constexpr size_t MasterCounterOffset = 336;
    constexpr size_t CounterStride = 32;
    // A key block holds this many counters, one per data block that follows it
    constexpr size_t DataBlocksPerKeyBlock = 512;

    // Counter mode, implemented by hand (CNG doesn't offer it): keystream = cipher(counter),
    // counter incremented after each block, little-endian per the reference implementation.
    class CounterMode
    {
    public:

        CounterMode(BCRYPT_KEY_HANDLE Key) : Aes(Key) {}

        void Reset(const uint8_t* Counter)
        {
            std::memcpy(Block, Counter, CounterSize);
            Used = CounterSize;
            Primed = false;
        }

        bool Apply(uint8_t* Data, size_t Length)
        {
            // whole blocks from a block's start: their counters laid out, then ciphered in one call
            // (a call per 16 bytes was most of a Modern Warfare WWII zone's opening)
            if (Used == CounterSize && Length >= CounterSize)
            {
                const size_t Blocks = Length / CounterSize;
                Stream.resize(Blocks * CounterSize);
                for (size_t K = 0; K < Blocks; K++)
                {
                    if (Primed)
                        for (size_t b = 0; b < CounterSize; b++)
                            if (++Block[b] != 0) break;
                    Primed = true;
                    std::memcpy(Stream.data() + K * CounterSize, Block, CounterSize);
                }
                ULONG Produced = 0;
                if (!BCRYPT_SUCCESS(BCryptEncrypt(Aes, Stream.data(), (ULONG)Stream.size(), nullptr, nullptr, 0, Stream.data(),
                                                  (ULONG)Stream.size(), &Produced, 0)))
                {
                    return false;
                }
                for (size_t i = 0; i < Stream.size(); i++) Data[i] ^= Stream[i];
                // the last block's pad all used: the next byte takes the next counter
                std::memcpy(Pad, Stream.data() + Stream.size() - CounterSize, CounterSize);
                Data += Stream.size();
                Length -= Stream.size();
            }
            for (size_t i = 0; i < Length; i++)
            {
                if (Used == CounterSize)
                {
                    // The first block uses the counter as given; every one after it
                    // increments first
                    if (Primed)
                    {
                        for (size_t b = 0; b < CounterSize; b++)
                        {
                            if (++Block[b] != 0)
                            {
                                break;
                            }
                        }
                    }

                    ULONG Produced = 0;
                    if (!BCRYPT_SUCCESS(BCryptEncrypt(Aes, Block, (ULONG)CounterSize, nullptr,
                        nullptr, 0, Pad, (ULONG)CounterSize, &Produced, 0)))
                    {
                        return false;
                    }

                    Used = 0;
                    Primed = true;
                }

                Data[i] ^= Pad[Used++];
            }

            return true;
        }

    private:

        BCRYPT_KEY_HANDLE Aes;
        std::vector<uint8_t> Stream;   // a run of counters, then their keystream
        uint8_t Block[CounterSize] = {};
        uint8_t Pad[CounterSize] = {};
        size_t Used = CounterSize;
        bool Primed = false;
    };

    // Unseals the 40 byte key. The DER is a PKCS#1 private key, which CNG will not import
    // directly, so it goes through the older decoder first to reach a blob CNG accepts.
    bool UnsealKey(const std::vector<uint8_t>& WorldWar2RsaKey, const uint8_t* Sealed, uint8_t* Out, std::string& Error)
    {
        DWORD BlobSize = 0;
        uint8_t* Blob = nullptr;

        if (!CryptDecodeObjectEx(X509_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY,
            WorldWar2RsaKey.data(), (DWORD)WorldWar2RsaKey.size(),
            CRYPT_DECODE_ALLOC_FLAG, nullptr, &Blob, &BlobSize))
        {
            Error = std::format("could not decode the private key (0x{:08X})", GetLastError());
            return false;
        }

        BCRYPT_ALG_HANDLE Algorithm = nullptr;
        BCRYPT_KEY_HANDLE Key = nullptr;
        auto Ok = false;

        if (BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&Algorithm, BCRYPT_RSA_ALGORITHM, nullptr, 0)) &&
            BCRYPT_SUCCESS(BCryptImportKeyPair(Algorithm, nullptr, LEGACY_RSAPRIVATE_BLOB,
                &Key, Blob, BlobSize, 0)))
        {
            BCRYPT_OAEP_PADDING_INFO Padding = {};
            Padding.pszAlgId = BCRYPT_SHA256_ALGORITHM;

            ULONG Produced = 0;

            if (BCRYPT_SUCCESS(BCryptDecrypt(Key, (PUCHAR)Sealed, (ULONG)SealedKeySize, &Padding,
                nullptr, 0, Out, (ULONG)UnsealedKeySize, &Produced, BCRYPT_PAD_OAEP)) &&
                Produced == UnsealedKeySize)
            {
                Ok = true;
            }
            else
            {
                Error = "the sealed key did not come out at forty bytes";
            }
        }
        else
        {
            Error = "could not import the private key";
        }

        if (Key != nullptr) BCryptDestroyKey(Key);
        if (Algorithm != nullptr) BCryptCloseAlgorithmProvider(Algorithm, 0);
        LocalFree(Blob);

        return Ok;
    }
}

bool WorldWar2::Decrypt(const std::string& FilePath, std::vector<uint8_t>& Out, std::string& Error, const Context& Ctx)
{
    Out.clear();
    Error.clear();

    std::vector<uint8_t> WorldWar2RsaKey;
    if (!GetKey(Ctx, keys::S2RsaPrivate, std::filesystem::path(FilePath), WorldWar2RsaKey, Error))
    {
        return false;
    }

    std::vector<uint8_t> File;
    if (!FastFileInternal::ReadWholeFile(FilePath, File, Error))
    {
        return false;
    }

    // A 32 byte header, two counted tables of sixteen byte entries, then twelve sizes
    size_t At = 32;

    for (int Table = 0; Table < 2; Table++)
    {
        if (At + 4 > File.size())
        {
            Error = "the header runs past the end of the file";
            return false;
        }

        uint32_t Entries = 0;
        std::memcpy(&Entries, File.data() + At, sizeof(Entries));
        At += 4 + (size_t)Entries * 16;
    }

    if (At + 96 + SealedKeySize + MasterBlockSize > File.size())
    {
        Error = "the file is too short to hold its key and master block";
        return false;
    }

    uint64_t Sizes[12] = {};
    std::memcpy(Sizes, File.data() + At, sizeof(Sizes));
    At += sizeof(Sizes);

    const auto Sealed = File.data() + At;
    At += SealedKeySize;

    // The master block is decrypted in place, since its counters are all that is wanted
    std::vector<uint8_t> Master(File.data() + At, File.data() + At + MasterBlockSize);
    At += MasterBlockSize;

    uint8_t Unsealed[UnsealedKeySize] = {};

    if (!UnsealKey(WorldWar2RsaKey, Sealed, Unsealed, Error))
    {
        return false;
    }

    BCRYPT_ALG_HANDLE Algorithm = nullptr;
    BCRYPT_KEY_HANDLE Aes = nullptr;

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&Algorithm, BCRYPT_AES_ALGORITHM, nullptr, 0)) ||
        !BCRYPT_SUCCESS(BCryptSetProperty(Algorithm, BCRYPT_CHAINING_MODE,
            (PUCHAR)BCRYPT_CHAIN_MODE_ECB, sizeof(BCRYPT_CHAIN_MODE_ECB), 0)) ||
        !BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(Algorithm, &Aes, nullptr, 0,
            Unsealed, (ULONG)AesKeySize, 0)))
    {
        Error = "could not set up the block cipher";
        if (Algorithm != nullptr) BCryptCloseAlgorithmProvider(Algorithm, 0);
        return false;
    }

    CounterMode Counter(Aes);

    // The counter for the master block is the tail of the unsealed key
    Counter.Reset(Unsealed + AesKeySize);

    auto Ok = Counter.Apply(Master.data(), Master.size());

    if (Ok)
    {
        // Everything up to the first declared size is content; the rest is padding
        const auto End = (Sizes[0] > At && Sizes[0] <= File.size()) ? (size_t)Sizes[0] : File.size();

        std::vector<uint8_t> Block(BlockSize);
        std::vector<uint8_t> Keys(BlockSize);

        size_t KeyBlockIndex = 0;
        size_t DataBlockIndex = 0;
        auto WantKeyBlock = true;

        // Hand back a whole fast file, not bare blocks: original header + zeroed table counts
        // (tables already consumed) + sizes - the result is an ordinary unsigned container.
        Out.reserve(End - At + 136);
        Out.insert(Out.end(), File.begin(), File.begin() + 32);
        // Mark it unsigned. What comes out is not signed any more, and leaving the signed
        // magic in place sends the reader straight back into decryption on its own output.
        Out[4] = 'u';
        Out.insert(Out.end(), 8, 0);
        Out.insert(Out.end(), (const uint8_t*)Sizes, (const uint8_t*)Sizes + sizeof(Sizes));

        while (At < End && Ok)
        {
            const auto Take = std::min(BlockSize, File.size() - At);
            std::memcpy(Block.data(), File.data() + At, Take);

            if (Take < BlockSize)
            {
                std::memset(Block.data() + Take, 0, BlockSize - Take);
            }

            At += Take;

            if (WantKeyBlock)
            {
                // A key block's own counter comes from the master block
                const auto Offset = MasterCounterOffset + KeyBlockIndex * CounterStride;

                if (Offset + CounterSize > Master.size())
                {
                    Error = "ran out of master counters";
                    Ok = false;
                    break;
                }

                Counter.Reset(Master.data() + Offset);
                KeyBlockIndex++;

                Keys = Block;
                Ok = Counter.Apply(Keys.data(), Keys.size());

                DataBlockIndex = 0;
                WantKeyBlock = false;
            }
            else
            {
                // And a data block's comes from the key block before it
                Counter.Reset(Keys.data() + DataBlockIndex * CounterStride);
                DataBlockIndex++;

                Ok = Counter.Apply(Block.data(), Block.size());

                if (Ok)
                {
                    Out.insert(Out.end(), Block.begin(), Block.end());
                }

                if (DataBlockIndex == DataBlocksPerKeyBlock)
                {
                    WantKeyBlock = true;
                }
            }
        }
    }

    BCryptDestroyKey(Aes);
    BCryptCloseAlgorithmProvider(Algorithm, 0);

    if (!Ok)
    {
        if (Error.empty())
        {
            Error = "decryption failed";
        }
        return false;
    }

    if (Out.empty())
    {
        Error = "nothing was decrypted";
        return false;
    }

    return true;
}

}   // namespace wolff
