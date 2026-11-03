#pragma once

// Infinite Warfare's streamed data, as its .ff header lists it: the shared-stream count at 0xc4 and
// the image-stream count at 0xcc, then from 0xd0 that many 24-byte records {start, end, pak index in
// the low 16 bits} (shared first) into assetfile<index>.pak / imagefile<index>.pak, four per
// streamed image (its four levels) in the order the zone loads its streamed images. An empty range
// has no data. The shared stream's records are the xmodelsurfs a level's zone keeps out of it: the
// loader reads them before the zone (DB_LoadXFile), so they belong to the zone the game sees.

#include <wolff/ZoneBytes.h>

#include <cstdint>
#include <filesystem>
#include <string>
#include <utility>
#include <vector>

namespace wolff::Iw7
{
    struct StreamRecord
    {
        uint64_t Start = 0, End = 0, Pak = 0;
    };

    // The image-stream records of a .ff (empty when the header does not hold them)
    std::vector<StreamRecord> ReadImageStreams(const std::string& FastFilePath);

    // The folder the paks of a zone sit in: beside the base zones, a localized zone one folder down
    // (french\fra_<zone>.ff)
    std::filesystem::path PakDir(const std::string& FastFilePath, const std::string& Pak);

    // One shared-stream record of assetfile<index>.pak (PakPath): a 0x8000-byte signed header, then
    // the IWC compressor ("\x02IWC", u64 size, then LZ4 blocks {u32 packed, u64 size} padded to 4) of
    // a one-asset stream: its XAsset {type, header} and the asset as the loader reads it. Empty when
    // it does not decode.
    std::vector<uint8_t> ReadSharedRecord(const std::string& PakPath, uint64_t Start, uint64_t End);

    // The shared stream's records of FastFilePath decoded and appended after Zone, in order (the
    // room made once); Appended gets each one's offset in Zone and its length. Records that do not
    // decode (or 16 bytes or less) are left out; a header without the table appends nothing.
    void AppendSharedStream(const std::string& FastFilePath, ZoneBytes& Zone, std::vector<std::pair<int64_t, int64_t>>& Appended);
}
