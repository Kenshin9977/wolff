#pragma once

// ResumeIndex - a zone's resume index: what opening a few assets of a zone takes instead of walking
// all of it. Each zone-level asset's resume point (where its walk starts, the stream memory's
// cursors there), the assets a caller may ask for by type and name -> the resume point holding
// them, and for the games that resolve by key or hash (Black Ops 6/7) the zone's keys and assets by
// hash. One file per zone, keyed by its tables and its bytes, in a folder the caller gives: written
// after a full walk (FromWalk, or WalkZone with IndexOptions), read by a partial one
// (ZoneTables::PartialWalk).

#include <wolff/ByteView.h>
#include <wolff/ZoneTables.h>

#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace wolff
{
    class InstallIndex;

    // The asset types an index tells apart, by name: a type's id is its place in the list. The
    // profile's TypeNames (the walker's type ids), or the caller's own list. The files keep the ids
    // alone: what reads a file uses the list it was written with.
    using TypeList = std::vector<std::string>;
    // Name's id in Types, UINT32_MAX when it is not there
    uint32_t TypeIdOf(const TypeList& Types, std::string_view Name);

    struct ZoneResume
    {
        uint64_t Size = 0;   // the zone's bytes (a zone beside is placed before they are read)
        std::vector<ZoneTables::ZoneResult::ResumePoint> Points;
        // (type id, NameHash, point) -> the resume point whose walk holds that asset, sorted
        std::vector<std::tuple<uint32_t, uint64_t, uint32_t>> Names;
        std::vector<std::pair<uint64_t, int64_t>> Keys;                  // keyed references, in stream order
        std::map<std::pair<std::string, uint64_t>, int64_t> ByHash;      // (type name, "" any; hash) -> asset
        // a type whose instances a caller counts over the whole zone -> each one's position, in walk order
        std::map<std::string, std::vector<int64_t>> Ranked;

        // the resume point of an asset by type and name, SIZE_MAX when the zone lists none
        size_t Find(uint32_t Type, std::string_view Name) const;
        size_t Find(const TypeList& Types, std::string_view Type, std::string_view Name) const;
    };

    namespace ResumeIndex
    {
        // An asset of the zone as a caller names it: its type (a name of the index's TypeList), its
        // name, and where its struct is in the zone
        struct Named
        {
            std::string Type;
            std::string Name;
            int64_t Pos = -1;
        };

        // an asset's key: its type id and its name in lower case, hashed (XXH3 64)
        uint64_t NameHash(uint32_t Type, std::string_view Name);
        // the file of a zone in Dir: its name, the tables it was walked with and the files it is read
        // from (each one's path, size and time written), "" when one of them is not there
        std::string FileFor(const std::filesystem::path& Dir, const std::string& ZonePath, const std::string& TablesKey,
                            const std::vector<std::string>& Sources);
        // the same, from the bytes walked (a zone read from inside an archive): their XXH3
        std::string FileFor(const std::filesystem::path& Dir, const std::string& ZonePath, const std::string& TablesKey, ByteView Bytes);
        bool Save(const std::string& File, const ZoneResume& Z);
        // false when missing, from another format or damaged (its checksum)
        bool Load(const std::string& File, ZoneResume& Z);
        // the file is there and of this format (its head alone read): else a full open writes it again
        bool IsCurrent(const std::string& File);

        // A zone's index from a full layout walk of it (Bytes the zone walked): its resume points;
        // with Rules.KeyMask, its keys and its assets by hash; each of Assets (its type in Types) ->
        // the point whose walk holds it; each of Ranked -> its instances' positions
        ZoneResume FromWalk(const ZoneTables::ZoneResult& R, ByteView Bytes, const ZoneTables::StreamRules& Rules,
                            const std::vector<Named>& Assets, const TypeList& Types, const std::vector<std::string>& Ranked = {});
        // Each zone-level asset by its type and the first string its walk read: the name most asset
        // types start with (not Black Ops 6/7's, named by hash). What WalkZone's index names by default.
        std::vector<Named> NamedByFirstString(const ZoneTables::ZoneResult& R, ByteView Bytes);
    }

    namespace ZoneTables
    {
        // What a full walk writes beside its result (WalkZone below): the zone's resume index, its
        // assets added to an install index, or both
        struct IndexOptions
        {
            std::string ResumeFile;   // ResumeIndex::FileFor; "" writes none
            TypeList Types;           // the resume index's types; empty: the walk's TypeNames
            // the zone's assets; empty: ResumeIndex::NamedByFirstString
            std::function<std::vector<ResumeIndex::Named>(const ZoneResult& R, ByteView Bytes)> Name;
            std::vector<std::string> Ranked;
            InstallIndex* Install = nullptr;   // its assets added as zone Zone's (their types added to its list)
            size_t Zone = 0;
        };

        // WalkZone with its layout, then its indexes written as Index says
        ZoneResult WalkZone(ByteView Buf, const Tables* T, const std::vector<std::string>& TypeNames, const StreamRules& Rules,
                            const IndexOptions& Index);
    }
}
