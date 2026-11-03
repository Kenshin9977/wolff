#include "BuiltinFormats.h"
#include "TreyarchZoneFormat.h"

// Black Ops 4 (T8): the Treyarch header, its default layout (0x20 bytes, count 0x10, list 0x18).
namespace wolff {
namespace
{
}
}

void wolff::ZoneTables::BuiltinFormatT8()
{
    static const TreyarchZoneFormat Format("t8");
    RegisterZoneFormat(Format);
}
