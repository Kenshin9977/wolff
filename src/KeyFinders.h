#pragma once

// The finders behind Keys.h: each reads one key out of what the game ships (or fetches it). They
// return candidates; Keys.cpp checks them. Never log a key's bytes.

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace wolff::keyfind
{
    using Bytes = std::vector<uint8_t>;

    // SHA-256 of Data as lower-case hex
    std::string Sha256Hex(const uint8_t* Data, size_t Size);

    // Black Ops 2's 32-byte Salsa20 key out of a t6*.exe (SteamStub 3.1 code section decrypted
    // first): each candidate the code builds before DB_SetKey
    bool T6FromExe(const std::filesystem::path& Exe, std::vector<Bytes>& Candidates, std::string& Error);

    // Call of Duty Online's PKCS#1 RSA private key (DER) and the 24-byte file key sealed with it
    // (RSA-OAEP, SHA-256) out of codoMP_client_shipRetail.exe. The key pair is checked (it imports
    // and a value round-trips); FileKey is left empty when no seal opens.
    bool CodolFromExe(const std::filesystem::path& Exe, Bytes& RsaDer, Bytes& FileKey, std::string& Error);

    // WWII's PKCS#1 RSA private key (DER) from Scobalula/s2_ff_killer's Key.h at Url (HTTPS)
    bool S2FromUrl(const std::wstring& Url, Bytes& RsaDer, std::string& Error);

    // A PKCS#1 private key that imports into CNG and whose public and private halves agree
    bool RsaKeyPairAgrees(const Bytes& Der);
}

namespace wolff::FastFileInternal
{
    // Key opens the Black Ops 2 fast file at Path: its first block decrypts and inflates
    bool T6KeyOpens(const uint8_t* Key, size_t KeySize, const std::filesystem::path& Path);
}
