#pragma once

// What a layout walk is used through: its pointers resolved (inline links, asset-list references,
// data back references through the stream layout, asset pointers followed the way resolve_deref
// does), partial walks grown to what their links reach, the profiles loaded once per name and the
// key of what a walk with one depends on.
//
// The per-game walk hooks are options here: a zone's own prefix offset (StreamRules::StartOffset,
// Infinite Warfare's shared stream), asset pointers followed or not (ResolveLinks'
// DerefAssetPointers: Black Ops 4, Ghosts), keyed references (StreamRules' keyed_refs, rewind:
// Black Ops 6/7).

#include <wolff/ByteView.h>
#include <wolff/ZoneTables.h>

#include <cstdint>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace wolff::ZoneTables
{
// A profile and its compiled tables, loaded once per name for the process (ZoneProfile)
struct LoadedProfile
{
    Profile Profile;
    Tables* Tables = nullptr;
    LoadedProfile() = default;
    ~LoadedProfile();
    LoadedProfile(const LoadedProfile&) = delete;
    LoadedProfile& operator=(const LoadedProfile&) = delete;
};
// The profile Name (LoadProfile with the process's roots), loaded once and kept; nullptr with Error
const LoadedProfile* ZoneProfile(const std::string& Name, std::string& Error);

// A back reference's block and offset in the stream memory, by the profile's encoding (no check
// on the top bits for the 64-bit default style: the caller has one already)
bool DecodeBackRef(const StreamRules& Rules, uint64_t Value, int& Block, int64_t& Off);

// Every pointer of a layout walk, resolved: inline links, asset-list references, data back
// references through the stream layout, and (DerefAssetPointers) asset pointers followed the way
// resolve_deref does. In application order; Counters say how many of each kind and how many stay
// unresolved. What ZonekitZone serves the live code, and what any other reader of a zone uses.
struct ResolvedLinks
{
    std::vector<std::pair<int64_t, int64_t>> Links;   // pointer field -> where its data is
    std::map<std::string, size_t> Counters;           // links_inline/asset/data/deref, refs_unresolved
};
// What resolving a partial walk's links (PartialWalk::Merged) takes from the zone's
// resume points instead of the reads it lacks: where each listed asset starts and its cursors there,
// the resident slots as the walks reserved them, the zone's keys and its assets by hash
struct ResolveHints
{
    const std::vector<ZoneResult::ResumePoint>* Points = nullptr;
    const std::vector<std::pair<uint64_t, int64_t>>* Keys = nullptr;               // every key of the zone, in stream order
    const std::map<std::pair<std::string, uint64_t>, int64_t>* ByHash = nullptr;   // (type name, "" any; hash) -> asset
    // Keys by key, the first of each (the filing the game's map keeps): built on the first use and
    // kept, a partial walk's rounds and links asking it again and again (millions of keys)
    const std::unordered_map<uint64_t, int64_t>& Keyed() const;

private:
    mutable std::shared_ptr<const std::unordered_map<uint64_t, int64_t>> KeyedOnce;
};
ResolvedLinks ResolveLinks(const ZoneResult& R, const StreamRules& Rules, bool DerefAssetPointers,
                           ByteView Zone = {}, const ResolveHints* Hints = nullptr);
// The resume points a partial walk's links reach that it has not walked yet: the owners of its back
// references' targets (data, slots, listed assets, keys, hashes) and of its inline links' targets
std::set<size_t> MissingOwners(const ZoneResult& M, const StreamRules& Rules,
                               const PartialWalk& Walk, const ResolveHints& Hints);
// Targets walked, then every resume point their links reach (MissingOwners), round after round;
// Seen: the walks a round has looked at already (kept between calls). False when a walk fails or
// more than AtMost points are walked. On the walker's stack (WalkOnLargeStack).
bool WalkReached(PartialWalk& Walk, const std::vector<size_t>& Targets, const StreamRules& Rules,
                 const ResolveHints& Hints, std::set<size_t>& Seen, size_t& Rounds, size_t AtMost = 4000);

// What a walk with this profile depends on (its tables, its stream layout), hashed: the key of
// anything kept from one (the install index, BO4's material books).
std::string ProfileKey(const LoadedProfile& Loaded);

// A zone walked with a profile, the layout on: what a report on one zone reads
struct ProfileWalk
{
    std::string Profile;              // the profile walked with
    int PointerSize = 8;              // its pointer fields' width
    ZoneResult R;
    size_t Reached = 0;               // the zone-level assets the walk entered
    size_t Walked = 0;                // ... and read whole
    bool Complete = false;            // walked to the end of the zone
    std::unordered_map<int64_t, int64_t> Links;   // inline pointer field -> where its data is

    // The text an inline string pointer at Field names, "" when it is not one
    std::string String(ByteView Zone, int64_t Field) const;
};
// False with Error when the zone's header does not parse
bool WalkWithProfile(const LoadedProfile& Loaded, ByteView Zone, ProfileWalk& Out, std::string& Error);
}
