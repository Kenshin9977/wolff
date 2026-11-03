#pragma once

// Where Wolff's keys come from when no KeyProvider gives them (GetKey asks these): each one found
// in its game's exe (s2_rsa_private, not there, fetched from Scobalula/s2_ff_killer at a pinned
// commit), checked by its SHA-256 or by what it opens, then cached per install. README: "Keys".

#include <wolff/Context.h>

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace wolff
{
    // %LOCALAPPDATA%\wolff\keys.json
    std::filesystem::path DefaultKeyCacheFile();

    // The install holding key Id's source for From (a file or a folder): From's folder or the first
    // one above it with the game's exe. Empty when none, or when the key comes from no install
    // (s2_rsa_private).
    std::filesystem::path FindKeyInstall(std::string_view Id, const std::filesystem::path& From);

    // Key Id found anew, without the cache: from Install's exe, or fetched (s2_rsa_private, when
    // Options.Network). Validated; false with Error (never the key's bytes). CheckFile: a file a
    // key whose hash is not the known one must open (a Black Ops 2 fast file).
    bool FindKey(std::string_view Id, const std::filesystem::path& Install, std::vector<uint8_t>& Out, std::string& Error,
                 const KeyOptions& Options = {}, const std::filesystem::path& CheckFile = {});

    // Forgets the keys found in this process (the cache file is left as it is)
    void ForgetFoundKeys();
}
