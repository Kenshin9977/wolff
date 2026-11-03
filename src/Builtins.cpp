#include <wolff/Codol.h>
#include <wolff/FastFile.h>
#include <wolff/Iwff.h>
#include <wolff/ZoneTables.h>

#include <mutex>

namespace wolff
{
    // Explicit, not static registration objects: from a static library the linker keeps only the
    // objects something references, and a self-registering object nothing names is silently dropped.
    void RegisterBuiltins()
    {
        static std::once_flag Once;
        std::call_once(Once, [] {
            Iwff::RegisterBuiltins();
            Codol::RegisterBuiltins();
            ZoneTables::RegisterBuiltinZoneFormats();
        });
    }
}
