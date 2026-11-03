#pragma once

#include <wolff/Context.h>

#include <cstdint>
#include <string>
#include <vector>

// Decrypts a signed WWII fast file. Scheme from Scobalula's `s2_ff_killer` (public domain): a
// 256-byte block is RSA-decrypted into an AES-192 key + counter, which decrypts a 16KB master
// block; that block seeds a two-level counter chain for alternating key/data blocks, each counter
// used once per 16KB block. Windows CNG supplies RSA/AES but has no counter mode, so it's run here
// over AES-ECB (all counter mode is). The RSA private key comes from the context (keys::S2RsaPrivate).
namespace wolff::WorldWar2
{
    // Reads the file and hands back its decrypted contents, which is then an ordinary
    // Sledgehammer container and can be decompressed like any other.
    bool Decrypt(const std::string& FilePath, std::vector<uint8_t>& Out, std::string& Error, const Context& Ctx = DefaultContext());
}
