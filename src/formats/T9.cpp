#include "BuiltinFormats.h"
#include "TreyarchZoneFormat.h"

// Black Ops Cold War (T9): the Treyarch header, its layout from profiles/t9 "zone_header"
// (0x28 bytes, count 0x18, list 0x20: the string ids pointer sits between).
namespace wolff {
namespace
{
}
}

void wolff::ZoneTables::BuiltinFormatT9()
{
    static const TreyarchZoneFormat Format("t9");
    RegisterZoneFormat(Format);
}
