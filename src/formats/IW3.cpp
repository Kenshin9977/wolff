#include "BuiltinFormats.h"
#include "Iw3ZoneFormat.h"

// Call of Duty 4 (IW3): XFile 0x2c (size, external size, 9 block sizes),
// then the IW3-family list and stream (Iw3ZoneFormat.h).
namespace wolff {
namespace
{
}
}

void wolff::ZoneTables::BuiltinFormatIW3()
{
    static const Iw3Family::ZoneFormat Format("iw3", 0x2c);
    RegisterZoneFormat(Format);
}
