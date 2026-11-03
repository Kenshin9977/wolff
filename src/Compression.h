#pragma once

#include <cstddef>
#include <cstdint>

struct libdeflate_decompressor;

namespace wolff::detail
{
    // The thread's libdeflate decompressor (about twice zlib's and miniz's speed): the one every
    // inflate of the library uses
    libdeflate_decompressor* Inflater();

    // One LZ4 block: the bytes it produced, 0 when it does not decode
    uint32_t DecompressLZ4Block(const int8_t* CompressedBuffer, int8_t* DecompressedBuffer, int32_t CompressedSize, int32_t DecompressedSize);

    // One zlib stream at In inflated into Out, at most OutAvail bytes (Got: how many); false when
    // it does not inflate or needs more room (bad data, a bad Adler-32)
    bool InflateZlib(const uint8_t* In, size_t InSize, uint8_t* Out, size_t OutAvail, size_t& Got);
}
