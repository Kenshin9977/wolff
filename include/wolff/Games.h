#pragma once

// Which title a fast file belongs to: one row per title (and per magic and version it ships), by
// the fast file's magic and version, with what tells apart the titles that share both.

#include <cstdint>
#include <string>
#include <vector>

namespace wolff
{
    struct GameModule
    {
        // Short engine name: "IW3".."IW8", "T4".."T9", "S1", "S2", "H1", "BO6", "BO7", "MWIII", "CODOL"
        const char* Engine;
        const char* Title;
        // The executable that identifies an install on disk, empty when several titles share one.
        const char* InstallMarker;
        // Magic plus version, because several titles share a magic and differ only by version.
        // Version 0: the magic alone identifies the title (titles sharing a magic name their version).
        const char* FastFileMagic;
        uint32_t    FastFileVersion;

        // When several rows share a magic and version (Black Ops 6 and 7, a campaign and a multiplayer
        // build), what tells their fast files apart, in this order: the nearest folder above the file
        // named InstallFolder ("cod24"), then ClaimsHeader, which reads the file's header (a loose
        // file). The claims of rows sharing a version must exclude each other.
        const char* InstallFolder = nullptr;
        bool (*ClaimsHeader)(const std::string& FastFilePath) = nullptr;
        // The zone-table profile reading this row's zones, when its title has several (nullptr: the
        // title's only one)
        const char* Profile = nullptr;
    };

    // Every title Wolff knows, in a fixed order
    const std::vector<GameModule>& GameModules();

    // The module matching a fastfile's magic and version, or nullptr when no row claims it. When
    // several rows share both, FastFilePath decides (InstallFolder, then ClaimsHeader); without a
    // path, or when none claims it, the row with neither, or nullptr.
    const GameModule* FindGameModule(const std::string& Magic, uint32_t Version, const std::string& FastFilePath = {});

    // The module of a fast file on disk, by its header and its path
    const GameModule* FindGameModuleForFile(const std::string& FastFilePath);
}
