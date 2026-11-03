#include <wolff/Games.h>

#include <wolff/FastFile.h>
#include <wolff/Iwff.h>

#include <algorithm>
#include <filesystem>

namespace wolff
{
    namespace
    {
        constexpr uint32_t SectionsSigned = 0x41464154; // "TAFA"
        constexpr uint32_t SectionsPlain = 0x46464154;  // "TAFF"
        // A section every Black Ops 7 header carries (41 962 files of cod25 and lpc) and no Black Ops 6
        // one does (10 413): how a loose file is told from Black Ops 6's, which shares header version 25
        constexpr uint32_t Bo7OnlySection = 0xd4cb9f1b;

        bool HasBo7Section(const std::vector<uint32_t>& Types)
        {
            return std::find(Types.begin(), Types.end(), Bo7OnlySection) != Types.end();
        }
        // Black Ops 6 by a loose file's header: cod24's are signed ("TAFA", all 10 013), sp24's are
        // not ("TAFF", all 400; the campaign's exe is another build, read by its own profile)
        bool Bo6Multiplayer(const std::string& Path)
        {
            uint32_t Magic = 0;
            std::vector<uint32_t> Types;
            return Iwff::ReadSections(Path, 0xe0, Magic, Types) && Magic == SectionsSigned && !HasBo7Section(Types);
        }
        bool Bo6Campaign(const std::string& Path)
        {
            uint32_t Magic = 0;
            std::vector<uint32_t> Types;
            return Iwff::ReadSections(Path, 0xe0, Magic, Types) && Magic == SectionsPlain && !HasBo7Section(Types);
        }
        bool Bo7Header(const std::string& Path)
        {
            uint32_t Magic = 0;
            std::vector<uint32_t> Types;
            return Iwff::ReadSections(Path, 0xe0, Magic, Types) && HasBo7Section(Types);
        }

        std::string LowerAscii(std::string S)
        {
            for (auto& C : S)
                if (C >= 'A' && C <= 'Z') C = (char)(C - 'A' + 'a');
            return S;
        }

        // Among rows sharing a magic and version, the one FastFilePath belongs to
        const GameModule* Disambiguate(const std::vector<const GameModule*>& Rows, const std::string& FastFilePath)
        {
            if (!FastFilePath.empty())
            {
                // The nearest folder above the file that names a row's install folder
                std::error_code Ec;
                auto Dir = std::filesystem::absolute(std::filesystem::path(FastFilePath), Ec).parent_path();
                for (; !Dir.empty(); Dir = Dir.parent_path())
                {
                    const auto Name = LowerAscii(Dir.filename().string());
                    for (const auto* Row : Rows)
                        if (Row->InstallFolder != nullptr && Name == LowerAscii(Row->InstallFolder))
                            return Row;
                    if (Dir == Dir.parent_path())
                        break;
                }
                for (const auto* Row : Rows)
                    if (Row->ClaimsHeader != nullptr && Row->ClaimsHeader(FastFilePath))
                        return Row;
            }
            for (const auto* Row : Rows)
                if (Row->InstallFolder == nullptr && Row->ClaimsHeader == nullptr)
                    return Row;
            return nullptr;
        }
    }

    const std::vector<GameModule>& GameModules()
    {
        // When rows share a magic and version and neither has a claim, the first one answers.
        static const std::vector<GameModule> Modules = {
            { "IW3", "Call of Duty 4",       "iw3sp.exe",           "IWffu100", 5,    },
            { "T4",  "World at War",         "codwaw.exe",          "TAffu100", 0,    },
            { "T4",  "World at War",         "codwaw.exe",          "IWffu100", 387,  },   // the PC zones
            { "T5",  "Black Ops",            "BlackOps.exe",        "TAff0100", 0,    },
            { "T5",  "Black Ops",            "BlackOps.exe",        "IWffu100", 473,  },   // the PC zones
            { "T6",  "Black Ops 2",          "t6zm.exe",            "TAff0100", 147,  },
            { "T6",  "Black Ops 2",          "t6zm.exe",            "TAffu100", 147,  },   // unsigned (OAT's Linker)
            { "IW4", "Modern Warfare 2",     "iw4sp.exe",           "IWffu100", 276,  },
            { "IW4", "Modern Warfare 2",     "iw4sp.exe",           "IWff0100", 276,  },   // signed zones
            { "IW5", "Modern Warfare 3",     "iw5sp.exe",           "IWffu100", 1,    },
            { "IW5", "Modern Warfare 3",     "iw5sp.exe",           "IWff0100", 1,    },   // signed zones
            // IWffa100 version 25, told apart by install folder or header (Iwff.h)
            { "BO6", "Black Ops 6", "cod24-cod.exe", "IWffa100", 0x19, "cod24", Bo6Multiplayer, "bo6" },
            { "BO6SP", "Black Ops 6 (campaign)", "sp24-cod.exe", "IWffa100", 0x19, "sp24", Bo6Campaign, "bo6sp" },
            { "BO7", "Black Ops 7", "cod.exe", "IWffa100", 0x19, "cod25", Bo7Header, "bo7" },
            // sealed IW4 streams (Codol.h), found inside the install's .ifs archives
            { "CODOL", "Call of Duty Online", "codoMP_client_shipRetail.exe", "IWff0100", 461 },
            // the Sledgehammer container (version 0x42)
            { "H1",  "Modern Warfare Remastered", "h1_mp64_ship.exe", "S1ffu100", 0x42 },
            { "H1",  "Modern Warfare Remastered", "h1_mp64_ship.exe", "S1ff0100", 0x42 },
            { "IW3", "Call of Duty 4: Modern Warfare", "iw3mp.exe", "IWffu100", 5 },
            // Ghosts ships each zone in one of two magics
            { "IW6", "Ghosts",               "iw6sp64_ship.exe",    "IWffu100", 565 },
            { "IW6", "Ghosts",               "iw6sp64_ship.exe",    "IWff0100", 565 },
            // the blocked LZ4 container, version 0x653
            { "IW7", "Infinite Warfare",     "iw7_ship.exe",        "IWff0100", 1619 },
            { "IW7", "Infinite Warfare",     "iw7_ship.exe",        "IWffu100", 1619 },
            { "IW8", "Modern Warfare (2019)", "ModernWarfare.exe", "IWffa100", 11 },
            { "MWIII", "Modern Warfare III (2023)", "cod23-cod.exe", "IWffa100", 24 },
            // WWII names its version; Advanced Warfare (version 0x72e) is the magic-only match for the
            // rest, signed zones included
            { "S1",  "Advanced Warfare",     "s1_sp64_ship.exe",    "S1ffu100", 0 },
            { "S1",  "Advanced Warfare",     "s1_sp64_ship.exe",    "S1ff0100", 0 },
            { "S2",  "WWII",                 "s2_sp64_ship.exe",    "S1ffu100", 5 },
            { "S2",  "WWII",                 "s2_sp64_ship.exe",    "S1ff0100", 5 },
            { "T4", "Call of Duty: World at War", "CoDWaW.exe", "IWffu100", 387 },
            { "T7",  "Black Ops 3",          "BlackOps3.exe",       "TAff0000", 0 },
            { "T8",  "Black Ops 4",          "BlackOps4.exe",       "TAff0000", 0x27F },
            // the magic is "TAFF" and the version its header's version section (FastFile::Identify)
            { "T9",  "Black Ops Cold War",   "BlackOpsColdWar.exe", "TAFF", 0x64 },
        };
        return Modules;
    }

    const GameModule* FindGameModuleForFile(const std::string& FastFilePath)
    {
        const auto Info = FastFile::Identify(FastFilePath);
        return FindGameModule(Info.Magic, Info.Version, FastFilePath);
    }

    const GameModule* FindGameModule(const std::string& Magic, const uint32_t Version, const std::string& FastFilePath)
    {
        const GameModule* MagicOnly = nullptr;
        std::vector<const GameModule*> Exact;

        for (const auto& Module : GameModules())
        {
            if (Magic != Module.FastFileMagic)
                continue;

            if (Module.FastFileVersion == Version)
            {
                Exact.push_back(&Module);
                continue;
            }

            // Remember a magic-only match, but keep looking: a title that names its version is the
            // more specific answer and should win over one that does not.
            if (Module.FastFileVersion == 0 && MagicOnly == nullptr)
                MagicOnly = &Module;
        }

        if (Exact.size() == 1)
            return Exact.front();
        if (!Exact.empty())
            return Disambiguate(Exact, FastFilePath);
        return MagicOnly;
    }
}
