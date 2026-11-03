#include "formats/BuiltinFormats.h"

#include <wolff/ZoneTables.h>

#include <mutex>

namespace wolff::ZoneTables
{
    void RegisterBuiltinZoneFormats()
    {
        static std::once_flag Once;
        std::call_once(Once, [] {
            BuiltinFormatCODOL();
            BuiltinFormatIW3();
            BuiltinFormatIW4();
            BuiltinFormatIW6();
            BuiltinFormatIW7();
            BuiltinFormatIW8();
            BuiltinFormatS1();
            BuiltinFormatS2();
            BuiltinFormatT4();
            BuiltinFormatT5();
            BuiltinFormatT6();
            BuiltinFormatT7();
            BuiltinFormatT8();
            BuiltinFormatT9();
            BuiltinFormatIwctx();
        });
    }
}
