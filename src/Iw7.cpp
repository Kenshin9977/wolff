#include <wolff/Iw7.h>

#include "Compression.h"

#include <algorithm>
#include <cstring>
#include <execution>
#include <format>
#include <fstream>

namespace fs = std::filesystem;

namespace wolff::Iw7
{
    namespace
    {
        constexpr uint64_t SharedCountAt = 0xc4, ImageCountAt = 0xcc, RecordsAt = 0xd0;
        static_assert(sizeof(StreamRecord) == 24, "a stream record is 24 bytes");

        template <class T>
        T At(const std::vector<uint8_t>& Bytes, size_t Offset)
        {
            T V{};
            if (Offset + sizeof(T) <= Bytes.size()) std::memcpy(&V, Bytes.data() + Offset, sizeof(T));
            return V;
        }
    }

    std::vector<StreamRecord> ReadImageStreams(const std::string& FastFilePath)
    {
        std::vector<StreamRecord> Out;
        std::ifstream F(FastFilePath, std::ios::binary);
        uint32_t Shared = 0, Images = 0;
        F.seekg(SharedCountAt);
        F.read(reinterpret_cast<char*>(&Shared), 4);
        F.seekg(ImageCountAt);
        F.read(reinterpret_cast<char*>(&Images), 4);
        if (!F || Shared > (1u << 20) || Images > (1u << 20)) return Out;
        Out.resize(Images);
        F.seekg((std::streamoff)(RecordsAt + (uint64_t)Shared * sizeof(StreamRecord)));
        F.read(reinterpret_cast<char*>(Out.data()), (std::streamsize)Images * sizeof(StreamRecord));
        if (!F) Out.clear();
        return Out;
    }

    fs::path PakDir(const std::string& FastFilePath, const std::string& Pak)
    {
        const fs::path Dir = fs::path(FastFilePath).parent_path();
        std::error_code Ec;
        if (fs::exists(Dir / Pak, Ec)) return Dir;
        return Dir.parent_path();
    }

    std::vector<uint8_t> ReadSharedRecord(const std::string& Pak, uint64_t Start, uint64_t End)
    {
        std::vector<uint8_t> Out;
        if (End <= Start || End - Start > (256u << 20)) return Out;
        std::ifstream F(Pak, std::ios::binary);
        std::vector<uint8_t> Raw((size_t)(End - Start));
        F.seekg((std::streamoff)Start);
        F.read(reinterpret_cast<char*>(Raw.data()), (std::streamsize)Raw.size());
        if (!F) return Out;
        constexpr uint32_t Compressor = 0x43574902;
        size_t Pos = 0;
        for (const size_t Candidate : { (size_t)0x8000, (size_t)0 })
            if (Candidate + 16 <= Raw.size() && At<uint32_t>(Raw, Candidate) == Compressor) { Pos = Candidate + 16; break; }
        if (Pos == 0) return Out;
        const uint64_t Total = At<uint64_t>(Raw, Pos - 12);
        if (Total > (512u << 20)) return Out;
        Out.reserve((size_t)Total);
        while (Out.size() < Total && Pos + 12 <= Raw.size())
        {
            const uint32_t Packed = At<uint32_t>(Raw, Pos);
            const uint64_t Size = At<uint64_t>(Raw, Pos + 4);
            Pos += 12;
            if (Packed == 0 || Size == 0 || Pos + Packed > Raw.size() || Out.size() + Size > Total) break;
            const size_t Was = Out.size();
            Out.resize(Was + (size_t)Size);
            if (detail::DecompressLZ4Block((const int8_t*)Raw.data() + Pos, (int8_t*)Out.data() + Was, (int32_t)Packed, (int32_t)Size) != (uint32_t)Size)
                return {};
            Pos = (Pos + Packed + 3) & ~(size_t)3;
        }
        if (Out.size() != Total) Out.clear();
        return Out;
    }

    void AppendSharedStream(const std::string& FastFilePath, ZoneBytes& Zone, std::vector<std::pair<int64_t, int64_t>>& Appended)
    {
        std::ifstream F(FastFilePath, std::ios::binary);
        uint32_t Shared = 0;
        F.seekg(SharedCountAt);
        F.read(reinterpret_cast<char*>(&Shared), 4);
        if (!F || Shared > (1u << 20)) return;
        std::vector<StreamRecord> Records(Shared);
        F.seekg(RecordsAt);
        F.read(reinterpret_cast<char*>(Records.data()), (std::streamsize)Shared * sizeof(StreamRecord));
        if (!F) return;
        // read side by side, then appended in order with the room made once (a zone of hundreds of
        // MB grown record by record was copied again at each growth)
        std::vector<std::vector<uint8_t>> Read(Records.size());
        std::for_each(std::execution::par, Records.begin(), Records.end(), [&](const StreamRecord& R) {
            const std::string Pak = std::format("assetfile{}.pak", (unsigned long long)(R.Pak & 0xffff));
            Read[(size_t)(&R - Records.data())] = ReadSharedRecord((PakDir(FastFilePath, Pak) / Pak).string(), R.Start, R.End);
        });
        size_t Adding = 0;
        for (const auto& One : Read)
            if (One.size() > 16) Adding += One.size();
        Zone.reserve(Zone.size() + Adding);
        for (const auto& One : Read)
        {
            if (One.size() <= 16) continue;
            Appended.emplace_back((int64_t)Zone.size(), (int64_t)One.size());
            Zone.insert(Zone.end(), One.begin(), One.end());
        }
    }
}
