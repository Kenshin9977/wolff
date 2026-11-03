#pragma once

#include <cstdint>
#include <span>

namespace wolff
{
    // Bytes read in place: a zone, a file, any buffer (a std::vector converts to it). What a reader
    // takes when it only reads, so the zone's storage is free to be other than a vector.
    using ByteView = std::span<const uint8_t>;
}
