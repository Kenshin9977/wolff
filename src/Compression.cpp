#include "Compression.h"

#include <lz4.h>
#include <libdeflate.h>

#include <memory>

namespace wolff::detail
{
    libdeflate_decompressor* Inflater()
    {
        thread_local std::unique_ptr<libdeflate_decompressor, decltype(&libdeflate_free_decompressor)> D(libdeflate_alloc_decompressor(),
                                                                                                         libdeflate_free_decompressor);
        return D.get();
    }

    uint32_t DecompressLZ4Block(const int8_t* CompressedBuffer, int8_t* DecompressedBuffer, int32_t CompressedSize, int32_t DecompressedSize)
    {
        const auto Result = LZ4_decompress_safe((const char*)CompressedBuffer, (char*)DecompressedBuffer, CompressedSize, DecompressedSize);
        return Result > 0 ? (uint32_t)Result : 0;
    }

    bool InflateZlib(const uint8_t* In, size_t InSize, uint8_t* Out, size_t OutAvail, size_t& Got)
    {
        Got = 0;
        return libdeflate_zlib_decompress(Inflater(), In, InSize, Out, OutAvail, &Got) == LIBDEFLATE_SUCCESS;
    }
}
