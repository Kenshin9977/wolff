#pragma once

// InstallIndex - where each asset of an install is defined: its zones, the assets each defines (by
// type and name, with what each weighs) and the parts (a type and a hash) each holds. Kept in a
// file read in place (.gwi: hash tables over the assets and the parts, each slot naming a list of
// zones; nothing loaded whole) under a key the caller gives. Built zone by zone (BuildZones), or
// from full walks (ZoneTables::IndexOptions). README.md, "Indexes".

#include <wolff/ResumeIndex.h>

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace wolff
{
    // What an asset weighs: Bytes what its zone holds of it (0: not known); A, B and C three numbers
    // of the caller's own (an image's width and height, a sound's frames...), 0 when not known
    struct AssetWeight
    {
        uint64_t Bytes = 0;
        uint32_t A = 0, B = 0, C = 0;
    };

    // An asset by type (an id in the index's TypeList) and name, the name compared without case
    struct IndexedAsset
    {
        uint32_t Type = 0;
        std::string Name;
        bool operator<(const IndexedAsset& O) const;
    };

    class InstallIndex
    {
    public:
        // Types: the ids the file keeps (at most 65536); a type added later goes after them
        explicit InstallIndex(TypeList Types = {});

        const TypeList& Types() const { return TypeNames; }
        uint32_t TypeId(std::string_view Name) const { return TypeIdOf(TypeNames, Name); }
        // its id, added to the list when it is not there
        uint32_t AddType(std::string_view Name);

        // Built in memory: the zones (what was there dropped), then what each defines and holds
        void SetZones(std::vector<std::string> Zones);
        void SetFootprint(size_t Zone, uint64_t Bytes) { Sizes[Zone] = Bytes; }
        void Add(size_t Zone, IndexedAsset A, AssetWeight W = {});
        void AddPart(size_t Zone, const std::string& Type, uint64_t Hash);

        // The file read in place when its key is Key (any key when Key is empty); false when it is
        // missing, another format or another key
        bool LoadMapped(const std::filesystem::path& Path, const std::string& Key);
        // what is in memory written (replacing the file once whole)
        bool SaveMapped(const std::filesystem::path& Path, const std::string& Key) const;
        // the text index of before (.idx: "greyhound-zone-index <Format>", "key <key>", a "zone" line
        // per zone, a "<type>\t<name>" line per asset, a "part\t<type>\t<hash>" line per part),
        // read in memory; a line of a type not in the list is skipped
        bool LoadText(const std::filesystem::path& Path, const std::string& Key, int Format);

        const std::vector<std::string>& Zones() const { return Names; }   // in the caller's order
        uint64_t Footprint(size_t Zone) const { return Sizes[Zone]; }
        // what Zone defines, in order, and what each weighs (none known: a file of before weights)
        void Read(size_t Zone, std::vector<IndexedAsset>& Assets, std::vector<AssetWeight>* Weights = nullptr) const;
        // the zones that define an asset, in zone order
        std::vector<size_t> DefinedIn(uint32_t Type, std::string_view Name) const;
        std::vector<size_t> DefinedIn(std::string_view Type, std::string_view Name) const;
        // the zones holding the part, in zone order
        std::vector<size_t> PartIn(const std::string& Type, uint64_t Hash) const;
        size_t Entries() const { return Count; }
        bool Weighed() const { return HasWeights; }   // false: kept before weights (version 1)
        bool Mapped() const { return Map != nullptr; }

        // Whether a name is text: UTF-8 without control bytes (a reader whose name pointer resolved
        // into other data gives bytes, which would cut the text files' lines)
        static bool TextName(std::string_view Name);
        // what the index keeps instead of a name that is not text: "#<type>_<FNV-1a of its bytes>"
        static std::string FallbackName(std::string_view Type, std::string_view Name);
        // a name's bytes for a report line: printable ASCII as it is, the rest \xNN, the first 48
        static std::string Escaped(std::string_view Name);

    private:
        TypeList TypeNames;
        std::vector<std::string> Names;
        std::vector<uint64_t> Sizes;
        std::vector<std::vector<IndexedAsset>> Assets;
        std::vector<std::vector<AssetWeight>> AssetWeights;
        size_t Count = 0;
        bool HasWeights = true;
        // (hashed: an index of every zone of an install holds millions of entries)
        struct AssetHash
        {
            size_t operator()(const IndexedAsset& A) const;
        };
        struct AssetSame
        {
            bool operator()(const IndexedAsset& A, const IndexedAsset& B) const { return !(A < B) && !(B < A); }
        };
        struct PartHash
        {
            size_t operator()(const std::pair<std::string, uint64_t>& P) const
            {
                return std::hash<std::string>()(P.first) ^ (size_t)(P.second * 0x9E3779B97F4A7C15ull);
            }
        };
        std::unordered_map<IndexedAsset, std::vector<size_t>, AssetHash, AssetSame> Where;
        std::unordered_map<std::pair<std::string, uint64_t>, std::vector<size_t>, PartHash> PartsWhere;
        struct Mapping;
        std::shared_ptr<const Mapping> Map;
    };

    // One zone's part of an index, as a build reads it (or a resumed build's partial file kept it)
    struct IndexedZone
    {
        bool Done = false;
        uint64_t Size = 0;   // its footprint, 0 when it does not open
        std::vector<IndexedAsset> Defined;   // sorted, once each
        std::vector<AssetWeight> Weights;    // beside Defined
        std::vector<std::pair<std::string, uint64_t>> Parts;   // sorted, once each
        std::vector<std::string> Renamed;   // "<zone>: <type> <its bytes> -> <name>": names that were not text
    };

    // How BuildZones reads an install's zones
    struct IndexBuild
    {
        std::vector<std::string> Zones;   // the index's zones, in order
        TypeList Types;                   // the index's types (the partial file names them)
        std::string Key;                  // the index's key: a partial file of another is started again
        int Format = 0;                   // the caller's format, in the partial file's head
        std::filesystem::path PartialFile;   // where the zones read so far are kept
        // the file a zone is read from, false when it has none (the caller serialises what must be)
        std::function<bool(size_t Zone, std::string& Path)> Resolve;
        // the zone read from that file (Done alone when it does not open)
        std::function<IndexedZone(size_t Zone, const std::string& Path)> Read;
        std::function<void(size_t Done, size_t Count)> Step;   // on the calling thread
        const std::atomic<bool>* Cancel = nullptr;
        unsigned Threads = 8;   // at most 8
        // the zones open at once stay under it (a zone's footprint estimated at 5 times its file;
        // a zone alone is always admitted)
        uint64_t BudgetBytes = 4096ull << 20;
    };

    // Every zone not read yet (Read[z].Done false) read by a pool of workers, admitted in zone order
    // within the budget; the partial file written as zones finish, so a build that stopped resumes
    // where it was. False when cancelled; an exception a worker threw is thrown again.
    bool BuildZones(const IndexBuild& Build, std::vector<IndexedZone>& Read);
    // What BuildZones read added to Index in zone order (its zones set first): the index a serial
    // build gives. Renamed: each zone's renamed names
    void AddZones(InstallIndex& Index, std::vector<IndexedZone>& Read, std::vector<std::string>* Renamed = nullptr);
}
