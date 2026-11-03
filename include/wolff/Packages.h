#pragma once

// The fast files of an install held in a file system (a Battle.net CASC storage: Black Ops 4, Cold
// War, Modern Warfare 2019...), pulled out to loose files a FastFile can read.

#include <wolff/FileSystem.h>

#include <string>
#include <vector>

namespace wolff::Packages
{
    // The fast file names (".ff") in the file system, sorted.
    std::vector<std::string> ListFastFiles(CoDFileSystem* FS);

    // Pulls the fast files matching Pattern (e.g. "*.ff", "zm_*.ff", or one file name) out of the
    // file system into CacheDir, each with its update patch (PatchExtension: .fd, Modern
    // Warfare 2019's .fp) when there is one; returns the .ff paths. A file already there at the
    // same size is not extracted again.
    std::vector<std::string> ExtractFastFiles(CoDFileSystem* FS, const std::string& Pattern, const std::string& CacheDir, std::string& Error,
                                              const char* PatchExtension = ".fd");

    // ExtractFastFiles for each of Names, the paths added to Out; false with Error when none is
    // (Install names the install there)
    bool ExtractZones(CoDFileSystem* FS, const std::string& Install, const std::vector<std::string>& Names, const std::string& CacheDir,
                      std::vector<std::string>& Out, std::string& Error, const char* PatchExtension = ".fd");
}
