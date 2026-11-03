// A layout walk's pointers resolved (ResolveLinks), a partial walk grown to what its links reach
// (WalkReached), the profile cache and its key, a fast file's zone walked with one (WalkWithProfile).
// Out of GrayWolf's ZonekitZone.cpp.

#include <wolff/ZoneLinks.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <mutex>
#include <unordered_set>

namespace fs = std::filesystem;

namespace wolff::ZoneTables
{
bool DecodeBackRef(const StreamRules& Rs, uint64_t Value, int& Block, int64_t& Off)
{
    if (Rs.Iw6Refs)
    {
        Block = (int)((Value >> 32) & 0xF);
        Off = (int64_t)(Value & 0xFFFFFFFFull) - 1;
        return true;
    }
    if (Rs.RefShift || Rs.PointerSize == 4 || Rs.Block32) return Rs.DecodeRef(Value, Block, Off);
    Block = (int)(Value >> 60);
    Off = (int64_t)(Value & 0x0FFFFFFFFFFFFFFFull) - 1;
    return true;
}

namespace
{
    uint64_t At64(ByteView Buf, int64_t Off)
    {
        uint64_t V = 0;
        if (Off >= 0 && Off + 8 <= (int64_t)Buf.size()) std::memcpy(&V, Buf.data() + Off, 8);
        return V;
    }

    uint64_t Fnv1a(const std::string& S, uint64_t H)
    {
        for (const unsigned char C : S) H = (H ^ C) * 0x100000001b3ull;
        return H;
    }
}

bool WalkReached(PartialWalk& PW, const std::vector<size_t>& Targets, const StreamRules& Rs,
                 const ResolveHints& H, std::set<size_t>& Seen, size_t& Rounds, size_t AtMost)
{
    bool Ok = true;
    for (const size_t P : Targets) Ok = Ok && PW.Walk(P) != nullptr;
    // each round looks only at the walks the rounds before have not (an owner walked on demand
    // included): what those reached is walked already
    while (Ok)
    {
        std::set<size_t> New;
        for (const auto& [P, Result] : PW.Walked())
            if (Seen.insert(P).second) New.insert(P);
        if (New.empty()) break;
        const std::set<size_t> More = MissingOwners(PW.Merged(&New), Rs, PW, H);
        Rounds++;
        if (More.empty()) break;
        for (const size_t P : More) Ok = Ok && PW.Walk(P) != nullptr;
        Ok = Ok && PW.Walked().size() <= AtMost;
    }
    return Ok;
}

namespace
{
    // A resident pointer (the marker_resident value) reserves a slot in the resident block
    // (resident_slot) holding where its data went, which is read elsewhere (often a block that
    // does not grow). A later back reference to that slot means that data: BO3 view models share
    // their LODs this way. The slot is where the block's cursor stood when the pointer was met,
    // right before its data's first read: the end of the block's last placed read, aligned.
    // Reserved, when given, gets each slot as {the read it comes before, its offset}.
    std::unordered_map<int64_t, int64_t> ResidentSlots(const ZoneResult& R, const StreamRules& Rs,
                                                       ByteView Zone,
                                                       std::vector<std::pair<size_t, int64_t>>* Reserved = nullptr)
    {
        std::unordered_map<int64_t, int64_t> Slots;
        if (Zone.empty() || Rs.ResidentSize <= 0 || Rs.ResidentAlign <= 0) return Slots;
        const int64_t Ptr = Rs.PointerSize == 4 ? 4 : 8;   // a pointer field's width
        // the resident pointers' data (a few per zone), then where each is first read
        std::unordered_map<int64_t, size_t> FirstRead;
        for (const auto& [Field, Target] : R.Links)
        {
            uint64_t V = 0;
            if (Field < 0 || Field + Ptr > (int64_t)Zone.size()) continue;
            std::memcpy(&V, Zone.data() + Field, (size_t)Ptr);
            if (V == Rs.SlotMarker) FirstRead.emplace(Target, SIZE_MAX);
        }
        for (size_t K = 0; K < R.ReadPos.size() && !FirstRead.empty(); K++)
            if (const auto It = FirstRead.find(R.ReadPos[K]); It != FirstRead.end() && It->second == SIZE_MAX) It->second = K;
        std::vector<std::pair<size_t, int64_t>> Events;   // the data's first read, the data
        for (const auto& [Field, Target] : R.Links)
        {
            uint64_t V = 0;
            if (Field < 0 || Field + Ptr > (int64_t)Zone.size()) continue;
            std::memcpy(&V, Zone.data() + Field, (size_t)Ptr);
            if (V != Rs.SlotMarker) continue;
            const auto It = FirstRead.find(Target);
            if (It->second != SIZE_MAX) Events.emplace_back(It->second, Target);
        }
        std::sort(Events.begin(), Events.end());
        int64_t Cursor = 0;
        size_t E = 0;
        for (size_t K = 0; K < R.Reads.size() && E < Events.size(); K++)
        {
            for (; E < Events.size() && Events[E].first == K; E++)
            {
                Cursor = (Cursor + Rs.ResidentAlign - 1) / Rs.ResidentAlign * Rs.ResidentAlign;
                Slots.emplace(Cursor, Events[E].second);
                if (Reserved != nullptr) Reserved->emplace_back(K, Cursor);
                Cursor += Rs.ResidentSize;
            }
            if (K < R.ReadMem.size() && R.ReadMem[K] >= 0 && (int)(R.ReadMem[K] >> 40) == Rs.ResidentBlock)
                Cursor = (R.ReadMem[K] & 0xFFFFFFFFFFll) + (R.Reads[K] < 0 ? -R.Reads[K] : R.Reads[K]);
        }
        return Slots;
    }
}

ResolvedLinks ResolveLinks(const ZoneResult& R, const StreamRules& Rs, bool DerefAssetPointers,
                           ByteView Zone, const ResolveHints* Hints)
{
    ResolvedLinks Out;
    // counted here, named once at the end: a name looked up per link was most of the time
    size_t Inline = R.Links.size(), Asset = 0, Resident = 0, Data = 0, Derefs = 0, Unresolved = 0;
    Out.Links.reserve(R.Links.size() + R.BackRefs.size());
    Out.Links.assign(R.Links.begin(), R.Links.end());

    // Zone-level instances come in list order, one per inline or resident header.
    std::vector<int64_t> AssetPos(R.AssetHeads.size(), -1);
    if (Hints && Hints->Points)
    {
        // a partial walk's: every listed asset where its resume point says it starts
        for (const auto& P : *Hints->Points)
            if (P.ListIndex < AssetPos.size()) AssetPos[P.ListIndex] = P.Pos;
    }
    else
    {
        std::vector<int64_t> Roots;
        for (const auto& I : R.Instances)
            if (I.Parent < 0) Roots.push_back(I.Pos);
        size_t Next = 0;
        for (size_t K = 0; K < R.AssetHeads.size() && Next < Roots.size(); K++)
            if (R.AssetHeads[K] == Rs.Marker || R.AssetHeads[K] == Rs.Resident) AssetPos[K] = Roots[Next++];
    }

    // A back reference names a block and an offset of the stream memory. The asset list sits in
    // the start block right before where the first asset loads (R.Start4, from the zone format);
    // a reference into its 16-byte slot k names asset k. Anything else is data an earlier read
    // placed, found through the layout (blocks.txt, empties.txt).
    const int64_t Entry = Rs.PointerSize == 4 ? 8 : 16;   // XAsset {type, header}
    const int64_t ListAt = R.Start4 - Entry * (int64_t)R.AssetHeads.size();
    const BlockMap Memory(R);
    std::vector<std::pair<size_t, int64_t>> Reserved;   // resident slots: the read each precedes, offset
    std::unordered_map<int64_t, int64_t> Slots;
    if (Hints && Hints->Points)
        for (const auto& [Off, Data] : R.Slots) Slots.emplace(Off, Data);   // as the walks reserved them
    else
        Slots = ResidentSlots(R, Rs, Zone, &Reserved);
    // stream.backref_asset_bit (IW8): such a reference counts from where the zone-level asset
    // holding the field began in its block; each root asset's block cursors at its first read.
    // A cursor counts the resident slots reserved up to there too, its own included (MWIII: the
    // -3 images a gfx_map holds take 8 bytes of block 15 each, no read; mp_jup_shipment_iw9's
    // map_ents begins 0x2c past its last read)
    std::vector<std::pair<int64_t, std::vector<int64_t>>> AssetStarts;   // root position -> cursors
    if (Rs.AssetBit > 0 && Hints && Hints->Points)
    {
        // a partial walk's: where each block's last read ended at its resume points
        for (const auto& P : *Hints->Points)
        {
            std::vector<int64_t> Cursor((size_t)std::max(Rs.StreamBlocks, 1), 0);
            for (const auto& [B, C] : P.Starts)
                if (B >= 0 && B < (int)Cursor.size()) Cursor[(size_t)B] = C;
            AssetStarts.emplace_back(P.Pos, std::move(Cursor));
        }
    }
    else if (Rs.AssetBit > 0)
    {
        std::unordered_map<int64_t, size_t> FirstRead;
        for (size_t K = 0; K < R.ReadPos.size(); K++) FirstRead.try_emplace(R.ReadPos[K], K);
        std::vector<std::pair<size_t, int64_t>> Roots;   // first read, position
        for (const auto& I : R.Instances)
            if (I.Parent < 0)
                if (const auto It = FirstRead.find(I.Pos); It != FirstRead.end()) Roots.emplace_back(It->second, I.Pos);
        std::sort(Roots.begin(), Roots.end());
        std::vector<int64_t> Cursor((size_t)std::max(Rs.StreamBlocks, 1), 0);
        if (Rs.StartBlock >= 0 && Rs.StartBlock < (int)Cursor.size()) Cursor[(size_t)Rs.StartBlock] = R.Start4;
        const bool SlotBlock = Rs.ResidentBlock >= 0 && Rs.ResidentBlock < (int)Cursor.size();
        size_t S = 0;   // the next reserved slot
        const auto Reserve = [&](size_t Before) {
            for (; S < Reserved.size() && Reserved[S].first <= Before; S++)
                if (SlotBlock) Cursor[(size_t)Rs.ResidentBlock] = Reserved[S].second + Rs.ResidentSize;
        };
        size_t K = Roots.empty() ? R.Reads.size() : Roots[0].first;
        for (const auto& [First, Pos] : Roots)
        {
            for (; K < First && K < R.ReadMem.size(); K++)
            {
                Reserve(K);
                if (R.ReadMem[K] >= 0 && (size_t)(R.ReadMem[K] >> 40) < Cursor.size())
                    Cursor[(size_t)(R.ReadMem[K] >> 40)] = (R.ReadMem[K] & 0xFFFFFFFFFFll) + (R.Reads[K] < 0 ? -R.Reads[K] : R.Reads[K]);
            }
            Reserve(First);
            AssetStarts.emplace_back(Pos, Cursor);
        }
        std::sort(AssetStarts.begin(), AssetStarts.end(), [](const auto& A, const auto& B) { return A.first < B.first; });
    }
    std::vector<std::pair<int64_t, int64_t>> Deref;   // field, referenced place
    // stream.keyed_refs (Black Ops 6/7): no stream layout; a data reference names the key an inline
    // pointer filed its data under (the first filing wins, as the game's map keeps it), an asset
    // reference the name hash at +0 of an asset instance of the zone
    // (an asset reference names an instance of the type its chain reads inline, R.RefTypes)
    std::unordered_map<uint64_t, int64_t> Keyed;   // the walk's own keys, under the hints' (Hints->Keyed)
    std::map<std::pair<uint16_t, uint64_t>, int64_t> Hashed;
    if (Rs.InlineBit > 0)
    {
        for (const auto& [Key, Pos] : R.Keys) Keyed.try_emplace(Key, Pos);
        if (!Zone.empty() && !Hints)
            for (const auto& I : R.Instances)
                if (I.Pos >= 0 && I.Pos + 8 <= (int64_t)Zone.size())
                    Hashed.try_emplace({ I.Owner, At64(Zone, I.Pos) & Rs.AssetHashMask }, I.Pos);
    }
    const auto KeyedAt = [&](uint64_t Key) -> int64_t {
        if (Hints)
            if (const auto It = Hints->Keyed().find(Key); It != Hints->Keyed().end()) return It->second;
        const auto It = Keyed.find(Key);
        return It == Keyed.end() ? -1 : It->second;
    };
    for (size_t K = 0; K < R.BackRefs.size(); K++)
    {
        const auto& [Field, Value] = R.BackRefs[K];
        if (Rs.InlineBit > 0)
        {
            const bool IsAsset = K < R.BackRefIsAsset.size() && R.BackRefIsAsset[K];
            int64_t Pos = -1;
            if (IsAsset)
            {
                const auto Type = R.RefTypes.find(Field);
                if (Hints)
                {
                    // the zone's assets by type name and hash, the walks' owner ids being their own
                    if (Type != R.RefTypes.end() && Type->second < R.OwnerNames.size())
                        if (Hints->ByHash != nullptr)
                            if (const auto It = Hints->ByHash->find({ R.OwnerNames[Type->second], Value & Rs.AssetHashMask }); It != Hints->ByHash->end())
                            Pos = It->second;
                }
                else
                {
                    const auto It = Type == R.RefTypes.end() ? Hashed.end() : Hashed.find({ Type->second, Value & Rs.AssetHashMask });
                    if (It != Hashed.end()) Pos = It->second;
                }
            }
            else
                Pos = KeyedAt(Value & Rs.KeyMask);
            if (Pos < 0)
            {
                Unresolved++;
                continue;
            }
            Out.Links.emplace_back(Field, Pos);
            (IsAsset ? Asset : Data)++;
            continue;
        }
        int Block = 0;
        int64_t Off = 0;
        if (!DecodeBackRef(Rs, Value, Block, Off))
        {
            Unresolved++;
            continue;
        }
        if (!Rs.Iw6Refs && (Rs.RefShift || Rs.PointerSize == 4 || Rs.Block32) && Rs.AssetRelative(Value))
        {
            auto It = std::upper_bound(AssetStarts.begin(), AssetStarts.end(), Field,
                                       [](int64_t F, const auto& A) { return F < A.first; });
            if (It == AssetStarts.begin() || (size_t)Block >= (--It)->second.size())
            {
                Unresolved++;
                continue;
            }
            Off += It->second[(size_t)Block];
        }
        if (Block == Rs.StartBlock && Off >= ListAt && Off < R.Start4)
        {
            const int64_t Pos = AssetPos[(size_t)((Off - ListAt) / Entry)];
            if (Pos >= 0)
            {
                Out.Links.emplace_back(Field, Pos);
                Asset++;
            }
            else
                Unresolved++;
            continue;
        }
        int64_t Pos = 0;
        if (!Memory.ZonePos(Block, Off, Pos))
        {
            // a resident pointer's slot: the reference names what that pointer points to
            const auto Slot = Block == Rs.ResidentBlock ? Slots.find(Off) : Slots.end();
            if (Slot == Slots.end())
            {
                Unresolved++;
                continue;
            }
            Out.Links.emplace_back(Field, Slot->second);
            Resident++;
            continue;
        }
        if (DerefAssetPointers && K < R.BackRefIsAsset.size() && R.BackRefIsAsset[K])
        {
            Deref.emplace_back(Field, Pos);
            continue;
        }
        Out.Links.emplace_back(Field, Pos);
        Data++;
    }
    // An asset pointer, where the game resolves it by reading the pointer at the referenced place
    // (IW6 resolve_deref): the asset is where that field points. Chains resolve in turn. A field's
    // target is its first inline link, else its last resolved one.
    if (!Deref.empty())
    {
        std::unordered_map<int64_t, int64_t> FieldTarget;
        FieldTarget.reserve(Out.Links.size());
        for (size_t K = 0; K < Out.Links.size(); K++)
            if (K < R.Links.size()) FieldTarget.try_emplace(Out.Links[K].first, Out.Links[K].second);
            else FieldTarget.insert_or_assign(Out.Links[K].first, Out.Links[K].second);
        for (bool Progress = true; Progress && !Deref.empty();)
        {
            Progress = false;
            std::vector<std::pair<int64_t, int64_t>> Waiting;
            for (const auto& [Field, Place] : Deref)
            {
                auto It = FieldTarget.find(Place);
                if (It == FieldTarget.end())
                {
                    Waiting.emplace_back(Field, Place);
                    continue;
                }
                const int64_t Target = It->second;
                Out.Links.emplace_back(Field, Target);
                FieldTarget.insert_or_assign(Field, Target);
                Derefs++;
                Progress = true;
            }
            Deref.swap(Waiting);
        }
    }
    Unresolved += Deref.size();
    auto& Counters = Out.Counters;
    for (const auto& [Name, N] : { std::pair<const char*, size_t>{ "links_inline", Inline }, { "links_asset", Asset },
                                   { "links_resident", Resident }, { "links_data", Data }, { "links_deref", Derefs } })
        if (N) Counters[Name] += N;
    Counters["refs_unresolved"] += Unresolved;
    return Out;
}

const std::unordered_map<uint64_t, int64_t>& ResolveHints::Keyed() const
{
    if (!KeyedOnce)
    {
        auto M = std::make_shared<std::unordered_map<uint64_t, int64_t>>();
        if (Keys != nullptr)
        {
            M->reserve(Keys->size());
            for (const auto& [Key, Pos] : *Keys) M->try_emplace(Key, Pos);
        }
        KeyedOnce = std::move(M);
    }
    return *KeyedOnce;
}

std::set<size_t> MissingOwners(const ZoneResult& M, const StreamRules& Rs,
                               const PartialWalk& Walk, const ResolveHints& Hints)
{
    std::set<size_t> Out;
    const auto& Walked = Walk.Walked();
    const auto Need = [&](size_t Point) {
        if (Point != SIZE_MAX && !Walked.count(Point)) Out.insert(Point);
    };
    const int64_t Entry = Rs.PointerSize == 4 ? 8 : 16;
    const int64_t ListAt = M.Start4 - Entry * (int64_t)M.AssetHeads.size();
    const auto& Keyed = Hints.Keyed();
    for (const auto& [Field, Target] : M.Links) Need(Walk.OwnerOf(Target));
    for (size_t K = 0; K < M.BackRefs.size(); K++)
    {
        const auto& [Field, Value] = M.BackRefs[K];
        if (Rs.InlineBit > 0)
        {
            int64_t Pos = -1;
            if (K < M.BackRefIsAsset.size() && M.BackRefIsAsset[K])
            {
                const auto Type = M.RefTypes.find(Field);
                if (Type != M.RefTypes.end() && Type->second < M.OwnerNames.size())
                    if (Hints.ByHash != nullptr)
                        if (const auto It = Hints.ByHash->find({ M.OwnerNames[Type->second], Value & Rs.AssetHashMask }); It != Hints.ByHash->end())
                        Pos = It->second;
            }
            else if (const auto It = Keyed.find(Value & Rs.KeyMask); It != Keyed.end())
                Pos = It->second;
            if (Pos >= 0) Need(Walk.OwnerOf(Pos));
            continue;
        }
        int Block = 0;
        int64_t Off = 0;
        if (!DecodeBackRef(Rs, Value, Block, Off)) continue;
        if (!Rs.Iw6Refs && (Rs.RefShift || Rs.PointerSize == 4 || Rs.Block32) && Rs.AssetRelative(Value))
        {
            const size_t Holder = Walk.OwnerOf(Field);
            if (Holder == SIZE_MAX) continue;
            for (const auto& [B, C] : Walk.ResumePoints()[Holder].Starts)
                if (B == Block) Off += C;
        }
        if (Block == Rs.StartBlock && Off >= ListAt && Off < M.Start4)
        {
            Need(Walk.PointOfListIndex((uint32_t)((Off - ListAt) / Entry)));
            continue;
        }
        Need(Walk.PlacedBy(Block, Off));
    }
    return Out;
}

std::string ProfileKey(const LoadedProfile& Loaded)
{
    // once per profile loaded (its tables read and hashed whole: Black Ops 7's zones beside asked it
    // 90 times, 2.2 s)
    static std::mutex Lock;
    static std::map<const LoadedProfile*, std::string> Known;
    {
        std::lock_guard<std::mutex> G(Lock);
        if (const auto It = Known.find(&Loaded); It != Known.end()) return It->second;
    }
    // what the walk and so the index depend on: the profile, its tables and its stream layout
    uint64_t H = 0xcbf29ce484222325ull;
    const auto Mix = [&H](const std::string& S) { H = Fnv1a(S, H); };
    const auto& P = Loaded.Profile;
    Mix(P.Name);
    std::vector<std::string> Files = P.TablePaths;
    for (const char* F : { "profile.json", "types.json", "blocks.txt", "empties.txt" }) Files.push_back((fs::path(P.Dir) / F).string());
    for (const auto& F : Files)
    {
        std::ifstream In(F, std::ios::binary);
        Mix(fs::path(F).filename().string() + "\n" + std::string(std::istreambuf_iterator<char>(In), std::istreambuf_iterator<char>()));
    }
    char B[40];
    snprintf(B, sizeof(B), "%s_%016llx", P.Name.c_str(), (unsigned long long)H);
    std::lock_guard<std::mutex> G(Lock);
    return Known.emplace(&Loaded, B).first->second;
}

std::string ProfileWalk::String(ByteView Zone, int64_t Field) const
{
    const auto It = Links.find(Field);
    if (It == Links.end()) return std::string();
    std::string S;
    for (int64_t Off = It->second; Off >= 0 && Off < (int64_t)Zone.size() && Zone[(size_t)Off]; Off++)
        S.push_back((char)Zone[(size_t)Off]);
    return S;
}

bool WalkWithProfile(const LoadedProfile& Loaded, ByteView Zone, ProfileWalk& Out, std::string& Error)
{
    const std::string Name = Out.Profile.empty() ? Loaded.Profile.Name : Out.Profile;
    Out = ProfileWalk();
    Out.Profile = Name;
    Out.PointerSize = Loaded.Profile.Rules.PointerSize;
    Out.R = WalkZone(Zone, Loaded.Tables, Loaded.Profile.TypeNames, Loaded.Profile.Rules, true);
    if (Out.R.ParseFailed)
    {
        Error = Out.R.Why;
        return false;
    }
    for (const auto& I : Out.R.Instances)
        if (I.Parent < 0) Out.Reached++;
    // the walk stops before an asset it has no table for, or after the end of the last one; any
    // other ending is an asset that raised, entered but not read whole
    Out.Complete = Out.R.Why == "walked to the end";
    const bool Raised = !Out.Complete && Out.R.Why.rfind("stopped ", 0) != 0 && Out.R.Why.rfind("no table for ", 0) != 0;
    Out.Walked = Out.Reached - (Raised && Out.Reached ? 1 : 0);
    Out.Links.reserve(Out.R.Links.size());
    for (const auto& [Field, Data] : Out.R.Links) Out.Links.emplace(Field, Data);
    return true;
}

LoadedProfile::~LoadedProfile()
{
    if (Tables != nullptr) FreeTables(Tables);
}

const LoadedProfile* ZoneProfile(const std::string& Name, std::string& Error)
{
    static std::mutex Lock;
    static std::map<std::string, std::unique_ptr<LoadedProfile>> Cache;
    std::lock_guard<std::mutex> Guard(Lock);
    auto It = Cache.find(Name);
    if (It != Cache.end()) return It->second.get();
    auto L = std::make_unique<LoadedProfile>();
    if (!LoadProfile(Name, L->Profile, Error)) return nullptr;
    try
    {
        L->Tables = LoadTables(L->Profile.TablePaths);
    }
    catch (const std::exception& E)
    {
        Error = E.what();
        return nullptr;
    }
    return (Cache[Name] = std::move(L)).get();
}
}
