#include <wolff/InstallIndex.h>

#include "MappedFile.h"

#define XXH_INLINE_ALL   // header-only: no xxhash library to link
#include <xxhash.h>

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <fstream>
#include <mutex>
#include <thread>

namespace fs = std::filesystem;

namespace wolff
{
namespace
{
    char LowerAscii(char C) { return (char)(C >= 'A' && C <= 'Z' ? C - 'A' + 'a' : C); }

    std::string Hex16(uint64_t V)
    {
        char B[17];
        snprintf(B, sizeof(B), "%016llx", (unsigned long long)V);
        return B;
    }

    uint64_t Fnv1a(std::string_view S)
    {
        uint64_t H = 0xcbf29ce484222325ull;
        for (const unsigned char C : S) H = (H ^ C) * 0x100000001b3ull;
        return H;
    }
}

bool IndexedAsset::operator<(const IndexedAsset& O) const
{
    if (Type != O.Type) return Type < O.Type;
    return _stricmp(Name.c_str(), O.Name.c_str()) < 0;
}

size_t InstallIndex::AssetHash::operator()(const IndexedAsset& A) const
{
    // FNV-1a over the name's lower-case letters, mixed with the type
    uint64_t H = 0xcbf29ce484222325ull ^ (uint64_t)A.Type;
    for (const char C : A.Name)
    {
        H ^= (uint8_t)LowerAscii(C);
        H *= 0x100000001b3ull;
    }
    return (size_t)H;
}

bool InstallIndex::TextName(std::string_view N)
{
    for (size_t I = 0; I < N.size();)
    {
        const uint8_t C = (uint8_t)N[I];
        if (C < 0x20 || C == 0x7f) return false;
        const size_t Len = C < 0x80 ? 1 : (C & 0xe0) == 0xc0 ? 2 : (C & 0xf0) == 0xe0 ? 3 : (C & 0xf8) == 0xf0 ? 4 : 0;
        if (Len == 0 || I + Len > N.size()) return false;
        for (size_t K = 1; K < Len; K++)
            if (((uint8_t)N[I + K] & 0xc0) != 0x80) return false;
        I += Len;
    }
    return true;
}

std::string InstallIndex::FallbackName(std::string_view Type, std::string_view N)
{
    return "#" + std::string(Type) + "_" + Hex16(Fnv1a(N));
}

std::string InstallIndex::Escaped(std::string_view N)
{
    static const char* Digits = "0123456789abcdef";
    std::string Out;
    for (size_t I = 0; I < N.size() && I < 48; I++)
    {
        const uint8_t C = (uint8_t)N[I];
        if (C >= 0x20 && C < 0x7f && C != '\\') Out += (char)C;
        else Out += std::string("\\x") + Digits[C >> 4] + Digits[C & 15];
    }
    return N.size() > 48 ? Out + "..." : Out;
}

InstallIndex::InstallIndex(TypeList Types) : TypeNames(std::move(Types)) {}

uint32_t InstallIndex::AddType(std::string_view Name)
{
    const uint32_t Id = TypeId(Name);
    if (Id != UINT32_MAX) return Id;
    TypeNames.emplace_back(Name);
    return (uint32_t)TypeNames.size() - 1;
}

void InstallIndex::SetZones(std::vector<std::string> Zones)
{
    Map.reset();
    Where.clear();
    PartsWhere.clear();
    Names = std::move(Zones);
    Sizes.assign(Names.size(), 0);
    Assets.assign(Names.size(), {});
    AssetWeights.assign(Names.size(), {});
    Count = 0;
    HasWeights = true;
}

void InstallIndex::Add(size_t Zone, IndexedAsset A, AssetWeight W)
{
    Where[A].push_back(Zone);
    AssetWeights[Zone].push_back(W);
    Assets[Zone].push_back(std::move(A));
    Count++;
}

void InstallIndex::AddPart(size_t Zone, const std::string& Type, uint64_t Hash)
{
    PartsWhere[{ Type, Hash }].push_back(Zone);
}

// The file: a header, the zones, the assets in zone order, and two open-addressing hash tables
// (linear probing, as cdb's) over the assets (type + lower-case name) and the parts (type + hash),
// each slot naming a list of zones. Little-endian; offsets from the file's start.
namespace
{
    constexpr char IndexMagic[4] = { 'G', 'W', 'Z', 'I' };
    // 2: each asset's weight after its name (1: none, read as unknown)
    constexpr uint32_t IndexVersion = 2;

#pragma pack(push, 1)
    struct FileHeader
    {
        char Magic[4];
        uint32_t Version;
        uint64_t KeyAt, KeyLength;
        uint64_t ZonesAt, ZoneCount;
        uint64_t AssetsAt, AssetCount;
        uint64_t AssetSlotsAt, AssetSlotCount;   // a power of two
        uint64_t PartSlotsAt, PartSlotCount;     // a power of two
        uint64_t ListsAt, ListsSize;
        uint64_t StringsAt, StringsSize;
    };
    struct FileZone
    {
        uint64_t Size, NameAt;
        uint32_t NameLength, FirstAsset, AssetCount, Pad;
    };
    struct FileAsset   // version 1's: the first 16 bytes
    {
        uint64_t NameAt;
        uint32_t NameLength;
        uint16_t Type;   // (a byte up to Wolff, the next one 0)
        uint8_t Pad[2];
        uint64_t Bytes;
        uint32_t A, B, C, Pad2;
    };
    constexpr uint64_t AssetStride1 = 16;
    struct FileSlot
    {
        uint64_t Hash;   // 0: empty
        uint64_t List;   // from ListsAt: an asset's {u32 asset, u32 count, count u32 zones}; a part's
                         // {u64 type at, u32 type length, u32 pad, u64 hash, u32 count, count u32 zones}
    };
#pragma pack(pop)

    uint64_t NameKey(uint32_t Type, std::string_view Name)
    {
        std::string L(Name);
        for (char& C : L) C = LowerAscii(C);
        const uint64_t H = XXH3_64bits_withSeed(L.data(), L.size(), (uint64_t)Type);
        return H ? H : 1;
    }
    uint64_t PartKey(std::string_view Type, uint64_t Hash)
    {
        const uint64_t H = XXH3_64bits_withSeed(Type.data(), Type.size(), Hash);
        return H ? H : 1;
    }
    uint64_t SlotsFor(size_t N)
    {
        uint64_t S = 16;
        while (S < (uint64_t)N * 2) S <<= 1;
        return S;
    }
    bool SameName(std::string_view A, std::string_view B)
    {
        if (A.size() != B.size()) return false;
        for (size_t K = 0; K < A.size(); K++)
            if (LowerAscii(A[K]) != LowerAscii(B[K])) return false;
        return true;
    }
}

struct InstallIndex::Mapping
{
    detail::MappedFile File;
    const uint8_t* Base = nullptr;
    uint64_t Size = 0;
    const FileHeader* Head = nullptr;
    uint64_t Stride = sizeof(FileAsset);   // a version 1 file's are shorter
    // the asset at Index, nullptr past the file (of a version 1 file, only its first 16 bytes)
    const FileAsset* Asset(uint64_t Index) const
    {
        const uint64_t Off = Head->AssetsAt + Index * Stride;
        return Holds(Off, Stride) ? reinterpret_cast<const FileAsset*>(Base + Off) : nullptr;
    }
    bool Holds(uint64_t At, uint64_t N) const { return At <= Size && N <= Size - At; }
    std::string_view Text(uint64_t At, uint64_t N) const
    {
        const uint64_t From = Head->StringsAt + At;
        return Holds(From, N) ? std::string_view((const char*)Base + From, (size_t)N) : std::string_view();
    }
    template <class T>
    const T* At(uint64_t Off, uint64_t Count = 1) const
    {
        return Holds(Off, Count * sizeof(T)) ? reinterpret_cast<const T*>(Base + Off) : nullptr;
    }
    // the slot list a key's probe ends at, 0 when the key is not there; Match checks a list
    template <class F>
    uint64_t Find(uint64_t SlotsAt, uint64_t Count, uint64_t Key, const F& Match) const
    {
        const FileSlot* Slots = At<FileSlot>(SlotsAt, Count);
        if (Slots == nullptr || Count == 0) return 0;
        for (uint64_t K = 0, S = Key & (Count - 1); K < Count; K++, S = (S + 1) & (Count - 1))
        {
            if (Slots[S].Hash == 0) return 0;
            if (Slots[S].Hash == Key && Match(Head->ListsAt + Slots[S].List)) return Head->ListsAt + Slots[S].List;
        }
        return 0;
    }
};

bool InstallIndex::LoadMapped(const fs::path& Path, const std::string& Key)
{
    auto M = std::make_shared<Mapping>();
    if (!M->File.Open(Path) || M->File.size() < sizeof(FileHeader)) return false;
    M->Base = M->File.data();
    M->Size = M->File.size();
    M->Head = reinterpret_cast<const FileHeader*>(M->Base);
    const FileHeader& H = *M->Head;
    if (std::memcmp(H.Magic, IndexMagic, 4) != 0 || (H.Version != IndexVersion && H.Version != 1)) return false;
    M->Stride = H.Version == 1 ? AssetStride1 : sizeof(FileAsset);
    if (!M->Holds(H.StringsAt, H.StringsSize) || !M->Holds(H.ListsAt, H.ListsSize) || M->At<FileZone>(H.ZonesAt, H.ZoneCount) == nullptr ||
        !M->Holds(H.AssetsAt, H.AssetCount * M->Stride) || M->At<FileSlot>(H.AssetSlotsAt, H.AssetSlotCount) == nullptr ||
        M->At<FileSlot>(H.PartSlotsAt, H.PartSlotCount) == nullptr)
        return false;
    if (!Key.empty() && M->Text(H.KeyAt, H.KeyLength) != Key) return false;
    SetZones({});
    HasWeights = H.Version != 1;
    const FileZone* Z = M->At<FileZone>(H.ZonesAt, H.ZoneCount);
    for (uint64_t K = 0; K < H.ZoneCount; K++)
    {
        Names.emplace_back(M->Text(Z[K].NameAt, Z[K].NameLength));
        Sizes.push_back(Z[K].Size);
    }
    Count = (size_t)H.AssetCount;
    Map = std::move(M);
    return true;
}

bool InstallIndex::SaveMapped(const fs::path& Path, const std::string& Key) const
{
    FileHeader H{};
    std::memcpy(H.Magic, IndexMagic, 4);
    H.Version = IndexVersion;
    std::string Strings;
    const auto Text = [&](std::string_view S) {
        const uint64_t At = Strings.size();
        Strings.append(S);
        return At;
    };
    H.KeyAt = Text(Key), H.KeyLength = Key.size();
    std::vector<FileZone> Zs(Names.size());
    std::vector<FileAsset> As;
    As.reserve(Count);
    for (size_t Z = 0; Z < Names.size(); Z++)
    {
        Zs[Z].Size = Sizes[Z];
        Zs[Z].NameAt = Text(Names[Z]), Zs[Z].NameLength = (uint32_t)Names[Z].size();
        Zs[Z].FirstAsset = (uint32_t)As.size(), Zs[Z].AssetCount = (uint32_t)Assets[Z].size();
        for (size_t I = 0; I < Assets[Z].size(); I++)
        {
            const IndexedAsset& A = Assets[Z][I];
            if (A.Type > 0xffff) return false;
            const AssetWeight W = I < AssetWeights[Z].size() ? AssetWeights[Z][I] : AssetWeight();
            As.push_back({ Text(A.Name), (uint32_t)A.Name.size(), (uint16_t)A.Type, {}, W.Bytes, W.A, W.B, W.C, 0 });
        }
    }
    // the lists, then the slots: each asset's first record (its name, to check) and its zones
    std::string Lists;
    const auto U32 = [&](uint32_t V) { Lists.append(reinterpret_cast<const char*>(&V), 4); };
    const auto U64 = [&](uint64_t V) { Lists.append(reinterpret_cast<const char*>(&V), 8); };
    std::vector<FileSlot> AssetSlots(SlotsFor(Where.size())), PartSlots(SlotsFor(PartsWhere.size()));
    const auto Place = [](std::vector<FileSlot>& Slots, uint64_t Key, uint64_t List) {
        for (uint64_t S = Key & (Slots.size() - 1);; S = (S + 1) & (Slots.size() - 1))
            if (Slots[S].Hash == 0)
            {
                Slots[S] = { Key, List };
                return;
            }
    };
    {
        // an asset's first record: the first zone defining it, its place among that zone's assets
        std::unordered_map<IndexedAsset, uint32_t, AssetHash, AssetSame> First;
        First.reserve(Where.size());
        for (size_t Z = 0, R = 0; Z < Names.size(); Z++)
            for (const IndexedAsset& A : Assets[Z]) First.try_emplace(A, (uint32_t)R++);
        for (const auto& [A, Zones] : Where)
        {
            const uint64_t List = Lists.size();
            U32(First[A]);
            U32((uint32_t)Zones.size());
            for (const size_t Z : Zones) U32((uint32_t)Z);
            Place(AssetSlots, NameKey(A.Type, A.Name), List);
        }
    }
    for (const auto& [Part, Zones] : PartsWhere)
    {
        const uint64_t List = Lists.size();
        U64(Text(Part.first));
        U32((uint32_t)Part.first.size());
        U32(0);
        U64(Part.second);
        U32((uint32_t)Zones.size());
        for (const size_t Z : Zones) U32((uint32_t)Z);
        Place(PartSlots, PartKey(Part.first, Part.second), List);
    }
    uint64_t At = sizeof(FileHeader);
    const auto Section = [&](uint64_t Bytes) {
        const uint64_t Here = (At + 7) & ~7ull;
        At = Here + Bytes;
        return Here;
    };
    H.ZonesAt = Section(Zs.size() * sizeof(FileZone)), H.ZoneCount = Zs.size();
    H.AssetsAt = Section(As.size() * sizeof(FileAsset)), H.AssetCount = As.size();
    H.AssetSlotsAt = Section(AssetSlots.size() * sizeof(FileSlot)), H.AssetSlotCount = AssetSlots.size();
    H.PartSlotsAt = Section(PartSlots.size() * sizeof(FileSlot)), H.PartSlotCount = PartSlots.size();
    H.ListsAt = Section(Lists.size()), H.ListsSize = Lists.size();
    H.StringsAt = Section(Strings.size()), H.StringsSize = Strings.size();
    std::string Out((size_t)At, '\0');
    const auto Put = [&](uint64_t Off, const void* P, size_t N) {
        if (N) std::memcpy(Out.data() + Off, P, N);
    };
    Put(0, &H, sizeof(H));
    Put(H.ZonesAt, Zs.data(), Zs.size() * sizeof(FileZone));
    Put(H.AssetsAt, As.data(), As.size() * sizeof(FileAsset));
    Put(H.AssetSlotsAt, AssetSlots.data(), AssetSlots.size() * sizeof(FileSlot));
    Put(H.PartSlotsAt, PartSlots.data(), PartSlots.size() * sizeof(FileSlot));
    Put(H.ListsAt, Lists.data(), Lists.size());
    Put(H.StringsAt, Strings.data(), Strings.size());
    std::error_code Ec;
    fs::create_directories(Path.parent_path(), Ec);
    fs::path Temp = Path;
    Temp += ".tmp";
    {
        std::ofstream F(Temp, std::ios::binary | std::ios::trunc);
        if (!F.write(Out.data(), (std::streamsize)Out.size())) return false;
    }
    fs::rename(Temp, Path, Ec);
    return !Ec;
}

void InstallIndex::Read(size_t Zone, std::vector<IndexedAsset>& Out, std::vector<AssetWeight>* Weights) const
{
    Out.clear();
    if (Weights) Weights->clear();
    if (Zone >= Names.size()) return;
    if (!Map)
    {
        Out = Assets[Zone];
        if (Weights) *Weights = AssetWeights[Zone];
        return;
    }
    const FileZone* Z = Map->At<FileZone>(Map->Head->ZonesAt + Zone * sizeof(FileZone));
    for (uint32_t K = 0; Z != nullptr && K < Z->AssetCount; K++)
    {
        const FileAsset* A = Map->Asset((uint64_t)Z->FirstAsset + K);
        if (A == nullptr) break;
        Out.push_back({ A->Type, std::string(Map->Text(A->NameAt, A->NameLength)) });
        if (Weights) Weights->push_back(Map->Stride == sizeof(FileAsset) ? AssetWeight{ A->Bytes, A->A, A->B, A->C } : AssetWeight());
    }
}

std::vector<size_t> InstallIndex::DefinedIn(uint32_t Type, std::string_view Name) const
{
    if (!Map)
    {
        const auto It = Where.find({ Type, std::string(Name) });
        return It == Where.end() ? std::vector<size_t>() : It->second;
    }
    const FileHeader& H = *Map->Head;
    const uint64_t List = Map->Find(H.AssetSlotsAt, H.AssetSlotCount, NameKey(Type, Name), [&](uint64_t L) {
        const uint32_t* First = Map->At<uint32_t>(L);
        const FileAsset* R = First ? Map->Asset(*First) : nullptr;
        return R != nullptr && R->Type == Type && SameName(Map->Text(R->NameAt, R->NameLength), Name);
    });
    std::vector<size_t> Out;
    const uint32_t* N = List ? Map->At<uint32_t>(List + 4) : nullptr;
    const uint32_t* Z = N ? Map->At<uint32_t>(List + 8, *N) : nullptr;
    for (uint32_t K = 0; Z != nullptr && K < *N; K++) Out.push_back(Z[K]);
    return Out;
}

std::vector<size_t> InstallIndex::DefinedIn(std::string_view Type, std::string_view Name) const
{
    const uint32_t Id = TypeId(Type);
    return Id == UINT32_MAX ? std::vector<size_t>() : DefinedIn(Id, Name);
}

std::vector<size_t> InstallIndex::PartIn(const std::string& Type, uint64_t Hash) const
{
    if (!Map)
    {
        const auto It = PartsWhere.find({ Type, Hash });
        return It == PartsWhere.end() ? std::vector<size_t>() : It->second;
    }
    const FileHeader& H = *Map->Head;
    const uint64_t List = Map->Find(H.PartSlotsAt, H.PartSlotCount, PartKey(Type, Hash), [&](uint64_t L) {
        const uint64_t* TypeAt = Map->At<uint64_t>(L);
        const uint32_t* TypeLength = Map->At<uint32_t>(L + 8);
        const uint64_t* Value = Map->At<uint64_t>(L + 16);
        return TypeAt && TypeLength && Value && *Value == Hash && Map->Text(*TypeAt, *TypeLength) == Type;
    });
    std::vector<size_t> Out;
    const uint32_t* N = List ? Map->At<uint32_t>(List + 24) : nullptr;
    const uint32_t* Z = N ? Map->At<uint32_t>(List + 28, *N) : nullptr;
    for (uint32_t K = 0; Z != nullptr && K < *N; K++) Out.push_back(Z[K]);
    return Out;
}

bool InstallIndex::LoadText(const fs::path& Path, const std::string& Key, int Format)
{
    // read whole and cut in place (an install's index can hold millions of lines)
    std::string Text;
    {
        std::ifstream In(Path, std::ios::binary);
        if (!In) return false;
        In.seekg(0, std::ios::end);
        const std::streamoff Size = In.tellg();
        if (Size <= 0) return false;
        Text.resize((size_t)Size);
        In.seekg(0);
        if (!In.read(Text.data(), Size)) return false;
    }
    size_t At = 0;
    const auto NextLine = [&](std::string_view& Line) {
        if (At >= Text.size()) return false;
        size_t End = Text.find('\n', At);
        if (End == std::string::npos) End = Text.size();
        Line = std::string_view(Text).substr(At, End - At);
        At = End + 1;
        return true;
    };
    std::string_view Line;
    if (!NextLine(Line) || Line != "greyhound-zone-index " + std::to_string(Format) || !NextLine(Line) || Line.rfind("key ", 0) != 0 ||
        (!Key.empty() && Line != "key " + Key))
        return false;
    SetZones({});
    std::string Type;
    {
        size_t PartLines = 0, Lines = 0;
        for (size_t P = Text.find('\n'); P != std::string::npos; P = Text.find('\n', P + 1))
        {
            Lines++;
            PartLines += Text.compare(P + 1, 5, "part\t") == 0;
        }
        PartsWhere.reserve(PartLines);
        Where.reserve(Lines - PartLines);
    }
    while (NextLine(Line))
    {
        const size_t Tab = Line.find('\t');
        if (Tab == std::string_view::npos) continue;
        const std::string_view Head = Line.substr(0, Tab);
        if (Head == "zone")
        {
            const size_t Tab2 = Line.find('\t', Tab + 1);
            if (Tab2 == std::string_view::npos) continue;
            Sizes.push_back(std::strtoull(Line.data() + Tab + 1, nullptr, 10));
            Names.emplace_back(Line.substr(Tab2 + 1));
            Assets.emplace_back();
            AssetWeights.emplace_back();
        }
        else if (Head == "part")
        {
            // part<TAB><type><TAB><hash, hex>
            const size_t Tab2 = Line.find('\t', Tab + 1);
            if (Tab2 == std::string_view::npos || Names.empty()) continue;
            Type.assign(Line.substr(Tab + 1, Tab2 - Tab - 1));
            PartsWhere[{ Type, std::strtoull(Line.data() + Tab2 + 1, nullptr, 16) }].push_back(Names.size() - 1);
        }
        else if (const uint32_t Id = TypeId(Head); !Names.empty() && Id != UINT32_MAX)
        {
            // (a file built before names were checked: the fallback a build gives now)
            std::string Name(Line.substr(Tab + 1));
            if (!TextName(Name)) Name = FallbackName(Head, Name);
            Add(Names.size() - 1, { Id, std::move(Name) });
        }
    }
    return true;
}

namespace
{
    // A build's partial file: each zone read so far, in the order they finished, so a build that
    // stopped (killed, cancelled) resumes where it was. "zone <n> <size> <name>", its asset and
    // part lines, then "end"; a record without its end is read again.
    const std::string PartialMagic = "greyhound-zone-index-partial ";

    void WriteEntry(std::ofstream& Out, const TypeList& Types, size_t Z, const std::string& Name, const IndexedZone& E)
    {
        Out << "zone\t" << Z << "\t" << E.Size << "\t" << Name << "\n";
        for (size_t I = 0; I < E.Defined.size(); I++)
        {
            const AssetWeight W = I < E.Weights.size() ? E.Weights[I] : AssetWeight();
            const uint32_t T = E.Defined[I].Type;
            Out << (T < Types.size() ? Types[T] : std::string("?")) << "\t" << W.Bytes << "\t" << W.A << "\t" << W.B << "\t" << W.C << "\t"
                << E.Defined[I].Name << "\n";
        }
        for (const auto& [Type, Hash] : E.Parts) Out << "part\t" << Type << "\t" << std::hex << Hash << std::dec << "\n";
        Out << "end\n";
        Out.flush();
    }

    // The complete records of a partial file with this key, then the file rewritten with them only
    // (a torn last record dropped) and left open to append to
    void ResumePartial(const IndexBuild& B, std::vector<IndexedZone>& Read, std::ofstream& Out)
    {
        const std::vector<std::string>& Names = B.Zones;
        {
            std::ifstream In(B.PartialFile, std::ios::binary);
            std::string Line;
            if (In && std::getline(In, Line) && Line == PartialMagic + std::to_string(B.Format) && std::getline(In, Line) && Line == "key " + B.Key)
            {
                size_t Z = SIZE_MAX;
                IndexedZone E;
                while (std::getline(In, Line))
                {
                    const size_t Tab = Line.find('\t');
                    if (Line == "end")
                    {
                        if (Z < Read.size())
                        {
                            E.Done = true;
                            Read[Z] = std::move(E);
                        }
                        Z = SIZE_MAX;
                        E = IndexedZone();
                    }
                    else if (Tab == std::string::npos) Z = SIZE_MAX;
                    else if (Line.compare(0, Tab, "zone") == 0)
                    {
                        E = IndexedZone();
                        const size_t Tab2 = Line.find('\t', Tab + 1), Tab3 = Tab2 == std::string::npos ? Tab2 : Line.find('\t', Tab2 + 1);
                        Z = Tab3 == std::string::npos ? SIZE_MAX : std::strtoull(Line.c_str() + Tab + 1, nullptr, 10);
                        if (Z < Names.size() && Line.substr(Tab3 + 1) == Names[Z]) E.Size = std::strtoull(Line.c_str() + Tab2 + 1, nullptr, 10);
                        else Z = SIZE_MAX;
                    }
                    else if (Z == SIZE_MAX) continue;
                    else if (Line.compare(0, Tab, "part") == 0)
                    {
                        const size_t Tab2 = Line.find('\t', Tab + 1);
                        if (Tab2 == std::string::npos) Z = SIZE_MAX;
                        else E.Parts.emplace_back(Line.substr(Tab + 1, Tab2 - Tab - 1), std::strtoull(Line.c_str() + Tab2 + 1, nullptr, 16));
                    }
                    else if (const uint32_t Type = TypeIdOf(B.Types, std::string_view(Line).substr(0, Tab)); Type != UINT32_MAX)
                    {
                        // <type> <bytes> <a> <b> <c> <name>
                        size_t From = Tab + 1;
                        uint64_t Fields[4] = {};
                        bool Whole = true;
                        for (uint64_t& F : Fields)
                        {
                            const size_t Next = Line.find('\t', From);
                            if (Next == std::string::npos) { Whole = false; break; }
                            F = std::strtoull(Line.c_str() + From, nullptr, 10);
                            From = Next + 1;
                        }
                        if (!Whole) { Z = SIZE_MAX; continue; }
                        std::string Name = Line.substr(From);
                        if (!InstallIndex::TextName(Name)) Name = InstallIndex::FallbackName(B.Types[Type], Name);
                        E.Defined.push_back({ Type, std::move(Name) });
                        E.Weights.push_back({ Fields[0], (uint32_t)Fields[1], (uint32_t)Fields[2], (uint32_t)Fields[3] });
                    }
                    else Z = SIZE_MAX;
                }
            }
        }
        Out.open(B.PartialFile, std::ios::binary | std::ios::trunc);
        Out << PartialMagic << B.Format << "\nkey " << B.Key << "\n";
        for (size_t Z = 0; Z < Read.size(); Z++)
            if (Read[Z].Done) WriteEntry(Out, B.Types, Z, Names[Z], Read[Z]);
        Out.flush();
    }
}

bool BuildZones(const IndexBuild& B, std::vector<IndexedZone>& Read)
{
    const std::vector<std::string>& Names = B.Zones;
    Read.resize(Names.size());
    std::ofstream Partial;
    ResumePartial(B, Read, Partial);
    std::vector<size_t> Todo;
    for (size_t Z = 0; Z < Names.size(); Z++)
        if (!Read[Z].Done) Todo.push_back(Z);
    size_t Finished = Names.size() - Todo.size();

    const unsigned Threads = std::min<unsigned>({ std::max(B.Threads, 1u), 8u, (unsigned)std::max<size_t>(Todo.size(), 1) });
    const uint64_t Budget = B.BudgetBytes;
    const std::atomic<bool>* Cancel = B.Cancel;

    std::mutex Lock;
    std::condition_variable Changed;
    size_t Next = 0, Admitted = 0, Running = Threads;
    uint64_t Open = 0;
    std::vector<std::pair<size_t, IndexedZone>> Ready;
    std::exception_ptr Failed;
    const auto Stopped = [&] { return (Cancel != nullptr && Cancel->load()) || Failed != nullptr; };

    const auto Work = [&] {
        for (;;)
        {
            size_t K;
            {
                std::lock_guard<std::mutex> G(Lock);
                if (Next >= Todo.size() || Stopped()) break;
                K = Next++;
            }
            const size_t Z = Todo[K];
            try
            {
                std::string Path;
                const bool Resolved = B.Resolve(Z, Path) && !Path.empty();
                std::error_code Ec;
                const uint64_t Bytes = Resolved ? fs::file_size(Path, Ec) : 0;
                const uint64_t Estimate = Ec ? 0 : Bytes * 5;
                {
                    // admitted in zone order, within the budget
                    std::unique_lock<std::mutex> G(Lock);
                    Changed.wait(G, [&] { return Stopped() || (Admitted == K && (Open == 0 || Open + Estimate <= Budget)); });
                    if (Admitted != K || Stopped()) break;
                    Admitted++;
                    Open += Estimate;
                }
                Changed.notify_all();
                IndexedZone E;
                E.Done = true;
                if (Resolved) E = B.Read(Z, Path);
                E.Done = true;
                {
                    std::lock_guard<std::mutex> G(Lock);
                    Open -= Estimate;
                    Ready.emplace_back(Z, std::move(E));
                }
            }
            catch (...)
            {
                std::lock_guard<std::mutex> G(Lock);
                if (!Failed) Failed = std::current_exception();
            }
            Changed.notify_all();
        }
        {
            std::lock_guard<std::mutex> G(Lock);
            Running--;
        }
        Changed.notify_all();
    };

    if (B.Step) B.Step(Finished, Names.size());
    std::vector<std::thread> Pool;
    if (Todo.empty()) Running = 0;
    else
        for (unsigned T = 0; T < Threads; T++) Pool.emplace_back(Work);
    for (bool More = !Pool.empty(); More;)
    {
        std::vector<std::pair<size_t, IndexedZone>> Got;
        {
            std::unique_lock<std::mutex> G(Lock);
            // (the cancel flag is set from elsewhere: looked at every half second)
            Changed.wait_for(G, std::chrono::milliseconds(500), [&] { return !Ready.empty() || Running == 0; });
            Got.swap(Ready);
            More = Running != 0;
        }
        if (Cancel != nullptr && Cancel->load()) Changed.notify_all();
        for (auto& [Z, E] : Got)
        {
            WriteEntry(Partial, B.Types, Z, Names[Z], E);
            Read[Z] = std::move(E);
            if (B.Step) B.Step(++Finished, Names.size());
        }
    }
    for (auto& T : Pool) T.join();
    if (Failed) std::rethrow_exception(Failed);
    if (Cancel != nullptr && Cancel->load()) return false;
    if (B.Step) B.Step(Names.size(), Names.size());
    return true;
}

void AddZones(InstallIndex& Index, std::vector<IndexedZone>& Read, std::vector<std::string>* Renamed)
{
    for (size_t Z = 0; Z < Read.size() && Z < Index.Zones().size(); Z++)
    {
        Index.SetFootprint(Z, Read[Z].Size);
        for (size_t I = 0; I < Read[Z].Defined.size(); I++)
            Index.Add(Z, std::move(Read[Z].Defined[I]), I < Read[Z].Weights.size() ? Read[Z].Weights[I] : AssetWeight());
        if (Renamed)
            for (auto& N : Read[Z].Renamed) Renamed->push_back(std::move(N));
        for (const auto& P : Read[Z].Parts) Index.AddPart(Z, P.first, P.second);
    }
}
}
