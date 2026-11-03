#include <wolff/Codol.h>

#include "Compression.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <cstring>

#pragma comment(lib, "bcrypt.lib")

namespace wolff {

namespace
{
    // The key (keys::CodolFileAes, GetKey: found in the exe) is the one the game unseals at start (0x66d0d0: the
    // 0x100 bytes at 0xda9708 through the fast files' RSA key, OAEP SHA-256), 24 bytes
    constexpr size_t FileKeySize = 24;
    constexpr size_t BlockSize = 0x8000;

    uint32_t NameNonce(const std::string& Base)
    {
        // CRC-32 (reflected, 0xEDB88320) whose register starts at ~length instead of ~0
        uint32_t Crc = ~(uint32_t)Base.size();
        for (const char Ch : Base)
        {
            Crc ^= (uint8_t)Ch;
            for (int K = 0; K < 8; K++) Crc = (Crc >> 1) ^ (0xEDB88320u & (0u - (Crc & 1)));
        }
        return ~Crc;
    }

    struct Aes
    {
        BCRYPT_ALG_HANDLE Alg = nullptr;
        BCRYPT_KEY_HANDLE Key = nullptr;
        explicit Aes(const std::vector<uint8_t>& FileKey)
        {
            if (BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&Alg, BCRYPT_AES_ALGORITHM, nullptr, 0)) &&
                BCRYPT_SUCCESS(BCryptSetProperty(Alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_ECB,
                                                 sizeof(BCRYPT_CHAIN_MODE_ECB), 0)))
                BCryptGenerateSymmetricKey(Alg, &Key, nullptr, 0, (PUCHAR)FileKey.data(), (ULONG)FileKey.size(), 0);
        }
        ~Aes()
        {
            if (Key) BCryptDestroyKey(Key);
            if (Alg) BCryptCloseAlgorithmProvider(Alg, 0);
        }
    };
}

bool Codol::UnwrapFile(const std::string& Name, std::vector<uint8_t>& Data, const Context& Ctx, const std::filesystem::path& From)
{
    if (Data.size() < 6) return false;
    std::vector<uint8_t> FileKey;
    std::string NoKey;
    if (!GetKey(Ctx, keys::CodolFileAes, From, FileKey, NoKey) || FileKey.size() != FileKeySize) return false;
    std::string Base = Name;
    if (const auto Slash = Base.find_last_of("/\\"); Slash != std::string::npos) Base = Base.substr(Slash + 1);
    uint32_t Unpacked = 0;
    std::memcpy(&Unpacked, Data.data() + Data.size() - 4, 4);
    const size_t Packed = Data.size() - 4;
    if (Unpacked == 0 || Unpacked > (1u << 30)) return false;

    Aes A(FileKey);
    if (A.Key == nullptr) return false;
    std::vector<uint8_t> Plain(Data.begin(), Data.begin() + Packed);
    const uint32_t Nonce = NameNonce(Base);
    std::vector<uint8_t> Stream;
    for (size_t Done = 0; Done < Packed; Done += BlockSize)
    {
        const size_t N = std::min(BlockSize, Packed - Done);
        uint8_t Counter[16];
        const uint32_t Fields[4] = { Nonce, Unpacked, (uint32_t)Done, (uint32_t)N };
        std::memcpy(Counter, Fields, 16);
        Stream.resize((N + 15) / 16 * 16);
        for (size_t At = 0; At < Stream.size(); At += 16)
        {
            std::memcpy(Stream.data() + At, Counter, 16);
            for (int B = 15; B >= 0 && ++Counter[B] == 0; B--) {}
        }
        ULONG Produced = 0;
        if (!BCRYPT_SUCCESS(BCryptEncrypt(A.Key, Stream.data(), (ULONG)Stream.size(), nullptr, nullptr, 0, Stream.data(),
                                          (ULONG)Stream.size(), &Produced, 0)))
            return false;
        for (size_t I = 0; I < N; I++) Plain[Done + I] ^= Stream[I];
    }
    if (Plain.empty() || Plain[0] != 0x78) return false;
    std::vector<uint8_t> Out(Unpacked);
    size_t Got = 0;
    if (!detail::InflateZlib(Plain.data(), Plain.size(), Out.data(), Out.size(), Got) || Got != Unpacked) return false;
    Data = std::move(Out);
    return true;
}

}   // namespace wolff
