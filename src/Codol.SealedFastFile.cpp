#include <wolff/Codol.h>
#include <wolff/FastFile.h>

#include "FastFileInternal.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <miniz/miniz.h>

#include <cstring>
#include <memory>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

namespace wolff {

namespace
{
    // The private key the game unseals with (PKCS#1 DER, at 0xdac4b0 in codoMP_client_shipRetail)
    // comes from GetKey (keys::CodolRsa: found in the exe).

    constexpr size_t HeaderSize = 21;
    constexpr size_t SealSize = 0x100;
    constexpr size_t KeySize = 24;
    constexpr size_t CounterSize = 16;
    constexpr size_t BlockSize = 0x2000;
    constexpr size_t HeaderHashes = 0x130;
    constexpr size_t HashSize = 32;
    constexpr size_t BlocksPerHashBlock = 256;

    struct Algorithms
    {
        BCRYPT_ALG_HANDLE Rsa = nullptr, Aes = nullptr, Sha = nullptr;
        ~Algorithms()
        {
            if (Rsa) BCryptCloseAlgorithmProvider(Rsa, 0);
            if (Aes) BCryptCloseAlgorithmProvider(Aes, 0);
            if (Sha) BCryptCloseAlgorithmProvider(Sha, 0);
        }
    };

    struct KeyHandle
    {
        BCRYPT_KEY_HANDLE H = nullptr;
        ~KeyHandle() { if (H) BCryptDestroyKey(H); }
    };

    bool Unseal(const Algorithms& A, const std::vector<uint8_t>& SealKey, const uint8_t* Sealed, uint8_t* Out, std::string& Error)
    {
        DWORD BlobSize = 0;
        uint8_t* Blob = nullptr;
        if (!CryptDecodeObjectEx(X509_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY, SealKey.data(), (DWORD)SealKey.size(),
                                 CRYPT_DECODE_ALLOC_FLAG, nullptr, &Blob, &BlobSize))
        {
            Error = "could not decode the sealing key";
            return false;
        }
        KeyHandle Key;
        bool Ok = false;
        if (BCRYPT_SUCCESS(BCryptImportKeyPair(A.Rsa, nullptr, LEGACY_RSAPRIVATE_BLOB, &Key.H, Blob, BlobSize, 0)))
        {
            ULONG Produced = 0;
            Ok = BCRYPT_SUCCESS(BCryptDecrypt(Key.H, (PUCHAR)Sealed, (ULONG)SealSize, nullptr, nullptr, 0, Out,
                                              (ULONG)(KeySize + CounterSize), &Produced, BCRYPT_PAD_PKCS1)) &&
                 Produced == KeySize + CounterSize;
            if (!Ok) Error = "the seal does not open to 40 bytes";
        }
        else
        {
            Error = "could not import the sealing key";
        }
        LocalFree(Blob);
        return Ok;
    }

    // One block in place: tomcrypt's counter mode, the counter incremented little-endian over all
    // 16 bytes after each AES block
    bool CounterMode(BCRYPT_KEY_HANDLE Aes, const uint8_t* Counter, uint8_t* Data, size_t Length)
    {
        std::vector<uint8_t> Stream((Length + CounterSize - 1) / CounterSize * CounterSize);
        uint8_t C[CounterSize];
        std::memcpy(C, Counter, CounterSize);
        for (size_t At = 0; At < Stream.size(); At += CounterSize)
        {
            std::memcpy(Stream.data() + At, C, CounterSize);
            for (size_t B = 0; B < CounterSize && ++C[B] == 0; B++) {}
        }
        ULONG Produced = 0;
        if (!BCRYPT_SUCCESS(BCryptEncrypt(Aes, Stream.data(), (ULONG)Stream.size(), nullptr, nullptr, 0,
                                          Stream.data(), (ULONG)Stream.size(), &Produced, 0)))
            return false;
        for (size_t I = 0; I < Length; I++)
            Data[I] ^= Stream[I];
        return true;
    }

    bool Sha256(BCRYPT_ALG_HANDLE Sha, const uint8_t* Data, size_t Length, uint8_t* Out)
    {
        BCRYPT_HASH_HANDLE H = nullptr;
        const bool Ok = BCRYPT_SUCCESS(BCryptCreateHash(Sha, &H, nullptr, 0, nullptr, 0, 0)) &&
                        BCRYPT_SUCCESS(BCryptHashData(H, (PUCHAR)Data, (ULONG)Length, 0)) &&
                        BCRYPT_SUCCESS(BCryptFinishHash(H, Out, (ULONG)HashSize, 0));
        if (H) BCryptDestroyHash(H);
        return Ok;
    }

    bool Decode(const std::string& FilePath, ByteView File, ZoneBytes& Zone, std::string& Error, const Context& Ctx)
    {
        return Codol::DecryptFastFile(File, Zone, Error, Ctx, std::filesystem::path(FilePath));
    }
}

void Codol::RegisterBuiltins()
{
    RegisterFastFileContainer("IWff0100", 461, Decode);
}

bool Codol::ReadZone(const Ifs::Install& Archives, const std::string& Folder, const std::string& Name, ZoneBytes& Zone, std::string& Error,
                     const Context& Ctx)
{
    const auto* L = Archives.Find(Folder + "/" + Name + ".ff");
    if (L == nullptr)
    {
        Error = "no " + Name + ".ff in the install's archives";
        return false;
    }
    std::vector<uint8_t> File;
    return Archives.Read(*L, File, Error) && DecryptFastFile(File, Zone, Error, Ctx, Ifs::Utf8Path(Archives.Folder()));
}

bool Codol::DecryptFastFile(ByteView File, ZoneBytes& Zone, std::string& Error, const Context& Ctx, const std::filesystem::path& From)
{
    Zone.clear();
    if (File.size() < HeaderSize + SealSize + BlockSize || (File.size() - HeaderSize - SealSize) % BlockSize != 0)
    {
        Error = "not a sealed fast file: its size is not the header, the seal and whole blocks";
        return false;
    }
    Algorithms A;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&A.Rsa, BCRYPT_RSA_ALGORITHM, nullptr, 0)) ||
        !BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&A.Aes, BCRYPT_AES_ALGORITHM, nullptr, 0)) ||
        !BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&A.Sha, BCRYPT_SHA256_ALGORITHM, nullptr, 0)) ||
        !BCRYPT_SUCCESS(BCryptSetProperty(A.Aes, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB,
                                          sizeof(BCRYPT_CHAIN_MODE_ECB), 0)))
    {
        Error = "could not open the ciphers";
        return false;
    }
    std::vector<uint8_t> SealKey;
    if (!GetKey(Ctx, keys::CodolRsa, From, SealKey, Error))
        return false;
    uint8_t Unsealed[KeySize + CounterSize] = {};
    if (!Unseal(A, SealKey, File.data() + HeaderSize, Unsealed, Error))
        return false;
    KeyHandle Aes;
    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(A.Aes, &Aes.H, nullptr, 0, Unsealed, (ULONG)KeySize, 0)))
    {
        Error = "could not set up the block cipher";
        return false;
    }

    const uint8_t* Body = File.data() + HeaderSize + SealSize;
    const size_t Blocks = (File.size() - HeaderSize - SealSize) / BlockSize;
    std::vector<uint8_t> Head(Body, Body + BlockSize), Hashes(BlockSize), Block(BlockSize);
    if (!CounterMode(Aes.H, Unsealed + KeySize, Head.data(), BlockSize) || std::memcmp(Head.data(), "IWffs100", 8) != 0)
    {
        Error = "the first block is not the IWffs100 header once decrypted";
        return false;
    }

    // Fast path: the blocks that check out, in order up to the first one that does not, inflated
    // whole by libdeflate. It succeeds exactly when the streaming loop below does (the stream ends
    // in blocks that check out), with the same bytes; on a failure, that loop runs for its error.
    {
        std::vector<uint8_t> Packed;
        Packed.reserve((Blocks - 1) * BlockSize);
        uint8_t Digest[HashSize];
        bool Checked = true;
        for (size_t Group = 1, I = 1; I < Blocks && Checked; Group++)
        {
            const size_t HashAt = HeaderHashes + HashSize * Group;
            if (HashAt + HashSize > BlockSize) break;
            const uint8_t* Expected = Head.data() + HashAt;
            std::memcpy(Hashes.data(), Body + I * BlockSize, BlockSize);
            if (!CounterMode(Aes.H, Expected, Hashes.data(), BlockSize) || !Sha256(A.Sha, Hashes.data(), BlockSize, Digest) ||
                std::memcmp(Digest, Expected, HashSize) != 0)
                break;
            I++;
            for (size_t K = 0; K < BlocksPerHashBlock && I < Blocks; K++, I++)
            {
                const uint8_t* Entry = Hashes.data() + HashSize * K;
                const size_t At = Packed.size();
                Packed.resize(At + BlockSize);
                std::memcpy(Packed.data() + At, Body + I * BlockSize, BlockSize);
                if (!CounterMode(Aes.H, Entry, Packed.data() + At, BlockSize) || !Sha256(A.Sha, Packed.data() + At, BlockSize, Digest) ||
                    std::memcmp(Digest, Entry, HashSize) != 0)
                {
                    Packed.resize(At);
                    Checked = false;
                    break;
                }
            }
        }
        std::string Unused;
        size_t Used = 0;
        if (!Packed.empty() && FastFileInternal::InflateInPlace(ByteView(Packed.data(), Packed.size()), Zone, Unused, &Used))
            return true;
        Zone.clear();
    }

    mz_stream Z = {};
    if (mz_inflateInit(&Z) != MZ_OK)
    {
        Error = "could not start inflating";
        return false;
    }
    std::unique_ptr<mz_stream, int (*)(mz_stream*)> Inflater(&Z, mz_inflateEnd);
    Zone.resize(Blocks * BlockSize * 3);
    size_t Out = 0;
    bool Ended = false;
    size_t I = 1;
    uint8_t Digest[HashSize];
    for (size_t Group = 1; I < Blocks && !Ended; Group++)
    {
        const size_t HashAt = HeaderHashes + HashSize * Group;
        if (HashAt + HashSize > BlockSize)
        {
            Error = "more hash blocks than the header lists";
            return false;
        }
        const uint8_t* Expected = Head.data() + HashAt;
        std::memcpy(Hashes.data(), Body + I * BlockSize, BlockSize);
        if (!CounterMode(Aes.H, Expected, Hashes.data(), BlockSize) || !Sha256(A.Sha, Hashes.data(), BlockSize, Digest) ||
            std::memcmp(Digest, Expected, HashSize) != 0)
        {
            Error = "hash block " + std::to_string(I) + " does not match the header";
            return false;
        }
        I++;
        for (size_t K = 0; K < BlocksPerHashBlock && I < Blocks && !Ended; K++, I++)
        {
            const uint8_t* Entry = Hashes.data() + HashSize * K;
            std::memcpy(Block.data(), Body + I * BlockSize, BlockSize);
            if (!CounterMode(Aes.H, Entry, Block.data(), BlockSize) || !Sha256(A.Sha, Block.data(), BlockSize, Digest) ||
                std::memcmp(Digest, Entry, HashSize) != 0)
            {
                Error = "block " + std::to_string(I) + " does not match its hash";
                return false;
            }
            Z.next_in = Block.data();
            Z.avail_in = (unsigned int)BlockSize;
            while (Z.avail_in > 0 && !Ended)
            {
                if (Out == Zone.size())
                    Zone.resize(Zone.size() * 2);
                Z.next_out = Zone.data() + Out;
                Z.avail_out = (unsigned int)(Zone.size() - Out);
                const int R = mz_inflate(&Z, MZ_SYNC_FLUSH);
                Out = Zone.size() - Z.avail_out;
                if (R == MZ_STREAM_END)
                    Ended = true;
                else if (R != MZ_OK && R != MZ_BUF_ERROR)
                {
                    Error = "the zone does not inflate at block " + std::to_string(I);
                    return false;
                }
                else if (R == MZ_BUF_ERROR && Z.avail_out > 0)
                    break;
            }
        }
    }
    if (!Ended)
    {
        Error = "the zone's stream ends before its last block";
        return false;
    }
    Zone.resize(Out);
    return true;
}

}   // namespace wolff
