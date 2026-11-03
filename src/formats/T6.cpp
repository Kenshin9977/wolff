#include "BuiltinFormats.h"
#include "Iw3ZoneFormat.h"

// Call of Duty: Black Ops II (T6): XFile 0x28 (size, external size, 8 block
// sizes), then the IW3-family list and stream (Iw3ZoneFormat.h) with a depends list after the
// strings; block 5 is current for the list.
namespace wolff {
namespace
{
}
}

void wolff::ZoneTables::BuiltinFormatT6()
{
    static const Iw3Family::ZoneFormat Format("t6", 0x28, true);
    RegisterZoneFormat(Format);
}
