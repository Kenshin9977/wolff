#include <wolff/ResumeIndex.h>
#include <wolff/InstallIndex.h>

#define XXH_INLINE_ALL   // header-only: no xxhash library to link
#include <xxhash.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <set>

namespace fs = std::filesystem;

namespace wolff
{
namespace
{
    constexpr char Magic[4] = { 'G', 'W', 'R', 'S' };
    // 2: Black Ops 7's keys and hashes; 3: Ranked; 4: Size; 7: a caller's image heads beside it
    constexpr uint32_t Version = 7;

    std::string Hex16(uint64_t V)
    {
        char B[17];
        snprintf(B, sizeof(B), "%016llx", (unsigned long long)V);
        return B;
    }

    // the bytes written: unsigned varints, zigzag for signed differences, raw u64 for hashes
    struct Writer
    {
        std::string B;
        void Var(uint64_t V)
        {
            while (V >= 0x80)
            {
                B.push_back((char)(V | 0x80));
                V >>= 7;
            }
            B.push_back((char)V);
        }
        void Zig(int64_t V) { Var(((uint64_t)V << 1) ^ (0 - ((uint64_t)V >> 63))); }
        void U64(uint64_t V) { B.append(reinterpret_cast<const char*>(&V), 8); }
        void Text(const std::string& S)
        {
            Var(S.size());
            B += S;
        }
    };

    struct Reader
    {
        const uint8_t* P;
        const uint8_t* End;
        bool Ok = true;
        uint64_t Var()
        {
            uint64_t V = 0;
            for (int Shift = 0; Shift < 64; Shift += 7)
            {
                if (P >= End) { Ok = false; return 0; }
                const uint8_t C = *P++;
                V |= (uint64_t)(C & 0x7f) << Shift;
                if (!(C & 0x80)) return V;
            }
            Ok = false;
            return 0;
        }
        int64_t Zig()
        {
            const uint64_t V = Var();
            return (int64_t)(V >> 1) ^ -(int64_t)(V & 1);
        }
        uint64_t U64()
        {
            if (End - P < 8) { Ok = false; return 0; }
            uint64_t V = 0;
            memcpy(&V, P, 8);
            P += 8;
            return V;
        }
        std::string Text()
        {
            const uint64_t N = Var();
            if (!Ok || (uint64_t)(End - P) < N) { Ok = false; return {}; }
            std::string S(reinterpret_cast<const char*>(P), (size_t)N);
            P += N;
            return S;
        }
        // a count no larger than what the bytes left could hold
        size_t Count()
        {
            const uint64_t N = Var();
            if (N > (uint64_t)(End - P)) Ok = false;
            return Ok ? (size_t)N : 0;
        }
    };

    std::string FileIn(const fs::path& Dir, const std::string& ZonePath, const std::string& Key)
    {
        return (Dir / (fs::path(ZonePath).stem().string() + "_" + Hex16(XXH3_64bits(Key.data(), Key.size())) + ".gwr")).string();
    }
}

uint32_t TypeIdOf(const TypeList& Types, std::string_view Name)
{
    for (size_t K = 0; K < Types.size(); K++)
        if (Types[K] == Name) return (uint32_t)K;
    return UINT32_MAX;
}

size_t ZoneResume::Find(uint32_t Type, std::string_view Name) const
{
    const std::tuple<uint32_t, uint64_t, uint32_t> Key{ Type, ResumeIndex::NameHash(Type, Name), 0 };
    auto It = std::lower_bound(Names.begin(), Names.end(), Key);
    if (It == Names.end() || std::get<0>(*It) != std::get<0>(Key) || std::get<1>(*It) != std::get<1>(Key)) return SIZE_MAX;
    return std::get<2>(*It);
}

size_t ZoneResume::Find(const TypeList& Types, std::string_view Type, std::string_view Name) const
{
    const uint32_t Id = TypeIdOf(Types, Type);
    return Id == UINT32_MAX ? SIZE_MAX : Find(Id, Name);
}

namespace ResumeIndex
{
    uint64_t NameHash(uint32_t Type, std::string_view Name)
    {
        std::string Lower(Name);
        for (auto& C : Lower) C = (char)std::tolower((unsigned char)C);
        return XXH3_64bits_withSeed(Lower.data(), Lower.size(), (uint64_t)Type);
    }

    std::string FileFor(const fs::path& Dir, const std::string& ZonePath, const std::string& TablesKey, const std::vector<std::string>& Sources)
    {
        std::string Key = TablesKey + "|files";
        std::error_code Ec;
        for (const std::string& S : Sources)
        {
            const fs::path P(S);
            const uintmax_t Size = fs::file_size(P, Ec);
            if (Ec) return std::string();
            const auto Written = fs::last_write_time(P, Ec);
            if (Ec) return std::string();
            Key += "|" + fs::absolute(P, Ec).string() + "|" + std::to_string(Size) + "|" + std::to_string(Written.time_since_epoch().count());
        }
        return FileIn(Dir, ZonePath, Key);
    }

    std::string FileFor(const fs::path& Dir, const std::string& ZonePath, const std::string& TablesKey, ByteView Bytes)
    {
        const uint64_t Content = XXH3_64bits(Bytes.data(), Bytes.size());
        return FileIn(Dir, ZonePath, TablesKey + "|" + std::to_string(Bytes.size()) + "|" + Hex16(Content));
    }

    bool Save(const std::string& File, const ZoneResume& Z)
    {
        Writer W;
        W.B.append(Magic, 4);
        W.B.append(reinterpret_cast<const char*>(&Version), 4);
        W.Var(Z.Size);
        // each point as differences from the one before: list slot, position, cursors (by block),
        // then where each block's last read ended, as a difference from that block's cursor
        W.Var(Z.Points.size());
        uint32_t PrevList = 0;
        int64_t PrevPos = 0;
        std::map<int, int64_t> PrevCursor;
        for (const auto& P : Z.Points)
        {
            W.Var(P.ListIndex - PrevList);
            W.Zig(P.Pos - PrevPos);
            W.Var(P.Cursors.size());
            std::map<int, int64_t> Here;
            for (const auto& [B, C] : P.Cursors)
            {
                W.Var((uint64_t)B);
                W.Zig(C - PrevCursor[B]);
                Here[B] = C;
            }
            W.Var(P.Starts.size());
            for (const auto& [B, C] : P.Starts)
            {
                W.Var((uint64_t)B);
                const auto It = Here.find(B);
                W.Zig(C - (It == Here.end() ? 0 : It->second));
            }
            PrevList = P.ListIndex;
            PrevPos = P.Pos;
            PrevCursor = std::move(Here);
        }
        W.Var(Z.Names.size());
        for (const auto& [T, H, P] : Z.Names)
        {
            W.Var(T);
            W.U64(H);
            W.Var(P);
        }
        W.Var(Z.Keys.size());
        int64_t PrevKeyPos = 0;
        for (const auto& [Key, Pos] : Z.Keys)
        {
            W.U64(Key);
            W.Zig(Pos - PrevKeyPos);
            PrevKeyPos = Pos;
        }
        std::map<std::string, uint64_t> Types;
        for (const auto& [K, Pos] : Z.ByHash) Types.emplace(K.first, 0);
        W.Var(Types.size());
        uint64_t N = 0;
        for (auto& [Name, Id] : Types)
        {
            Id = N++;
            W.Text(Name);
        }
        W.Var(Z.ByHash.size());
        for (const auto& [K, Pos] : Z.ByHash)
        {
            W.Var(Types[K.first]);
            W.U64(K.second);
            W.Zig(Pos);
        }
        W.Var(Z.Ranked.size());
        for (const auto& [Type, All] : Z.Ranked)
        {
            W.Text(Type);
            W.Var(All.size());
            int64_t Prev = 0;
            for (const int64_t Pos : All)
            {
                W.Zig(Pos - Prev);
                Prev = Pos;
            }
        }
        W.U64(XXH3_64bits(W.B.data(), W.B.size()));

        std::error_code Ec;
        fs::create_directories(fs::path(File).parent_path(), Ec);
        const std::string Temp = File + ".tmp";
        {
            std::ofstream Out(Temp, std::ios::binary | std::ios::trunc);
            if (!Out.write(W.B.data(), (std::streamsize)W.B.size())) return false;
        }
        fs::rename(Temp, File, Ec);
        return !Ec;
    }

    bool Load(const std::string& File, ZoneResume& Z)
    {
        std::ifstream In(File, std::ios::binary | std::ios::ate);
        if (!In) return false;
        std::vector<uint8_t> B((size_t)In.tellg());
        In.seekg(0);
        if (B.size() < 16 || !In.read(reinterpret_cast<char*>(B.data()), (std::streamsize)B.size())) return false;
        uint64_t Sum = 0;
        memcpy(&Sum, B.data() + B.size() - 8, 8);
        if (Sum != XXH3_64bits(B.data(), B.size() - 8)) return false;
        uint32_t V = 0;
        memcpy(&V, B.data() + 4, 4);
        if (memcmp(B.data(), Magic, 4) != 0 || V != Version) return false;
        Reader R{ B.data() + 8, B.data() + B.size() - 8 };
        Z = ZoneResume();
        Z.Size = R.Var();
        Z.Points.resize(R.Count());
        uint32_t PrevList = 0;
        int64_t PrevPos = 0;
        // per block the previous point's cursor, and this point's (blocks are a few small numbers):
        // a block the previous point had no cursor for counts from 0, as Save wrote it
        std::vector<int64_t> PrevCursor, Here;
        std::vector<uint8_t> PrevHas, Has;
        const auto Slot = [](std::vector<int64_t>& V, std::vector<uint8_t>& H, size_t B) {
            if (B >= V.size()) { V.resize(B + 1, 0); H.resize(B + 1, 0); }
        };
        for (auto& P : Z.Points)
        {
            P.ListIndex = PrevList + (uint32_t)R.Var();
            P.Pos = PrevPos + R.Zig();
            std::fill(Has.begin(), Has.end(), 0);
            const size_t NC = R.Count();
            P.Cursors.reserve(NC);
            for (size_t K = 0; K < NC && R.Ok; K++)
            {
                const uint64_t Block = R.Var();
                if (Block > 4096) { R.Ok = false; break; }
                Slot(Here, Has, (size_t)Block);
                const int64_t From = Block < PrevCursor.size() && PrevHas[(size_t)Block] ? PrevCursor[(size_t)Block] : 0;
                const int64_t C = From + R.Zig();
                P.Cursors.emplace_back((int)Block, C);
                Here[(size_t)Block] = C;
                Has[(size_t)Block] = 1;
            }
            const size_t NS = R.Count();
            P.Starts.reserve(NS);
            for (size_t K = 0; K < NS && R.Ok; K++)
            {
                const uint64_t Block = R.Var();
                const int64_t From = Block < Here.size() && Has[(size_t)Block] ? Here[(size_t)Block] : 0;
                P.Starts.emplace_back((int)Block, From + R.Zig());
            }
            PrevList = P.ListIndex;
            PrevPos = P.Pos;
            std::swap(PrevCursor, Here);
            std::swap(PrevHas, Has);
            if (!R.Ok) return false;
        }
        Z.Names.resize(R.Count());
        for (auto& [T, H, P] : Z.Names)
        {
            T = (uint32_t)R.Var();
            H = R.U64();
            P = (uint32_t)R.Var();
        }
        Z.Keys.resize(R.Count());
        int64_t PrevKeyPos = 0;
        for (auto& [Key, Pos] : Z.Keys)
        {
            Key = R.U64();
            Pos = PrevKeyPos + R.Zig();
            PrevKeyPos = Pos;
        }
        std::vector<std::string> Types(R.Count());
        for (auto& T : Types) T = R.Text();
        for (size_t K = 0, N = R.Count(); K < N && R.Ok; K++)
        {
            const uint64_t Type = R.Var();
            const uint64_t Hash = R.U64();
            const int64_t Pos = R.Zig();
            if (Type < Types.size()) Z.ByHash.emplace_hint(Z.ByHash.end(), std::make_pair(Types[(size_t)Type], Hash), Pos);   // written in order
        }
        for (size_t K = 0, N = R.Count(); K < N && R.Ok; K++)
        {
            std::vector<int64_t>& All = Z.Ranked[R.Text()];
            All.resize(R.Count());
            int64_t Prev = 0;
            for (int64_t& Pos : All) Pos = Prev = Prev + R.Zig();
        }
        return R.Ok && R.P == R.End;
    }

    bool IsCurrent(const std::string& File)
    {
        std::ifstream In(File, std::ios::binary);
        char Head[8] = {};
        uint32_t V = 0;
        if (!In.read(Head, 8)) return false;
        std::memcpy(&V, Head + 4, 4);
        return std::memcmp(Head, Magic, 4) == 0 && V == Version;
    }

    ZoneResume FromWalk(const ZoneTables::ZoneResult& R, ByteView Bytes, const ZoneTables::StreamRules& Rules, const std::vector<Named>& Assets,
                        const TypeList& Types, const std::vector<std::string>& Ranked)
    {
        ZoneResume Z;
        Z.Size = Bytes.size();
        Z.Points = R.Resume;
        std::vector<int64_t> Starts;
        Starts.reserve(Z.Points.size());
        for (const auto& P : Z.Points) Starts.push_back(P.Pos);
        // each asset a caller may ask for -> the resume point whose walk holds it
        for (const Named& A : Assets)
        {
            const uint32_t Type = TypeIdOf(Types, A.Type);
            auto It = std::upper_bound(Starts.begin(), Starts.end(), A.Pos);
            if (Type == UINT32_MAX || It == Starts.begin()) continue;
            Z.Names.emplace_back(Type, NameHash(Type, A.Name), (uint32_t)(It - Starts.begin() - 1));
        }
        std::sort(Z.Names.begin(), Z.Names.end());
        Z.Names.erase(std::unique(Z.Names.begin(), Z.Names.end()), Z.Names.end());
        // keyed references and assets by hash (Black Ops 6/7: keyed_refs or rewind_prepare): what a
        // partial walk cannot learn
        if (Rules.KeyMask != 0)
        {
            Z.Keys.assign(R.Keys.begin(), R.Keys.end());
            for (const auto& I : R.Instances)
                if (I.Pos >= 0 && (uint64_t)I.Pos + 8 <= Bytes.size() && I.Owner < R.OwnerNames.size())
                {
                    uint64_t H = 0;
                    std::memcpy(&H, Bytes.data() + I.Pos, 8);
                    H &= Rules.AssetHashMask;
                    Z.ByHash.try_emplace({ R.OwnerNames[I.Owner], H }, I.Pos);
                    Z.ByHash.try_emplace({ std::string(), H }, I.Pos);
                }
        }
        for (const std::string& T : Ranked)
        {
            std::vector<int64_t>& All = Z.Ranked[T];
            for (const auto& I : R.Instances)
                if (I.Owner < R.OwnerNames.size() && R.OwnerNames[I.Owner] == T) All.push_back(I.Pos);
        }
        return Z;
    }

    std::vector<Named> NamedByFirstString(const ZoneTables::ZoneResult& R, ByteView Bytes)
    {
        std::vector<Named> Out;
        for (const auto& I : R.Instances)
        {
            if (I.Parent >= 0 || I.Owner >= R.OwnerNames.size()) continue;
            for (uint32_t K = I.FirstRead; K < I.EndRead && K < R.Reads.size() && K < R.ReadPos.size(); K++)
            {
                if (R.Reads[K] >= 0) continue;
                const int64_t From = R.ReadPos[K];
                if (From < 0 || (uint64_t)From >= Bytes.size()) break;
                const char* S = reinterpret_cast<const char*>(Bytes.data() + From);
                const size_t N = strnlen(S, Bytes.size() - (size_t)From);
                if (N > 0) Out.push_back({ R.OwnerNames[I.Owner], std::string(S, N), I.Pos });
                break;
            }
        }
        return Out;
    }
}

namespace ZoneTables
{
    ZoneResult WalkZone(ByteView Buf, const Tables* T, const std::vector<std::string>& TypeNames, const StreamRules& Rules,
                        const IndexOptions& Index)
    {
        ZoneResult R = WalkZone(Buf, T, TypeNames, Rules, true);
        if (R.ParseFailed || (Index.ResumeFile.empty() && Index.Install == nullptr)) return R;
        const std::vector<ResumeIndex::Named> Assets = Index.Name ? Index.Name(R, Buf) : ResumeIndex::NamedByFirstString(R, Buf);
        if (!Index.ResumeFile.empty() && !R.Resume.empty())
            ResumeIndex::Save(Index.ResumeFile, ResumeIndex::FromWalk(R, Buf, Rules, Assets, Index.Types.empty() ? TypeNames : Index.Types, Index.Ranked));
        if (Index.Install != nullptr && Index.Zone < Index.Install->Zones().size())
        {
            // once each, as a build lists them
            std::set<IndexedAsset> Seen;
            for (const auto& A : Assets)
            {
                if (A.Name.empty()) continue;
                IndexedAsset Id{ Index.Install->AddType(A.Type), InstallIndex::TextName(A.Name) ? A.Name : InstallIndex::FallbackName(A.Type, A.Name) };
                if (Seen.insert(Id).second) Index.Install->Add(Index.Zone, std::move(Id));
            }
            Index.Install->SetFootprint(Index.Zone, Buf.size());
        }
        return R;
    }
}
}
