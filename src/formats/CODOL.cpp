#include "BuiltinFormats.h"
#include "Iw3ZoneFormat.h"

// Call of Duty Online: XFile 0x28 (size, external size, 8 block sizes),
// then the IW3-family list and stream (Iw3ZoneFormat.h) with 16-byte asset entries {u32 type, u32,
// u32 header, u32}; block 3 is current for the list.
namespace wolff {
namespace
{
}
}

void wolff::ZoneTables::BuiltinFormatCODOL()
{
    static const Iw3Family::ZoneFormat Format("codol", 0x28, false, 16, 8);
    RegisterZoneFormat(Format);
}
