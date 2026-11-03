# Wolff

A Call of Duty fast file reader (C++20, Windows). A fast file in, its zone out: decrypted,
decompressed, its update patch applied; which title it belongs to; the archives and storages the
files ship in; and the zone walked with reader tables transcribed from the game's own loaders.
Extracted from [GrayWolf](https://github.com/Kenshin9977/GrayWolf), which reads it through vcpkg.

## What it reads

| Container | Titles |
|---|---|
| zlib stream (`IWffu100`/`IWff0100`, signed and 64-bit variants) | CoD4, World at War, Black Ops, MW2, MW3, Ghosts |
| Salsa20 blocks (`TAff0100`, `TAffu100`) | Black Ops II |
| chunked (`TAff0000`), `.fd` VCDIFF patch | Black Ops III, Black Ops 4 (Oodle 6) |
| flexible (`TAFF`/`TAFA`), `.fd` patch | Black Ops Cold War (Oodle 8) |
| LZ4 blocks (`S1ffu100`/`S1ff0100`) | Advanced Warfare, MW Remastered, WWII (signed) |
| blocked LZ4 (`IWff0100`/1619), shared stream | Infinite Warfare |
| `IWffa100` (versions 11, 24, 25), `.fp` patch | MW 2019, MW III, Black Ops 6, Black Ops 7 (Oodle 7/8) |
| sealed IW4 stream (`IWff0100`/461), `.ifs` archives | Call of Duty Online |

```cpp
#include <wolff/Wolff.h>

wolff::RegisterBuiltins();
wolff::ZoneBytes Zone;
std::string Error;
const std::string Path = "C:/Games/Call of Duty Black Ops II/zone/all/mp_raid.ff";
if (!wolff::FastFile::Decompress(Path, Zone, Error))
    std::puts(Error.c_str());
const wolff::GameModule* Game = wolff::FindGameModuleForFile(Path);
```

## Keys

Wolff carries no key. The first time a container needs one, Wolff finds it, checks it and
caches it:

| Key | Game | Where it comes from |
|---|---|---|
| `t6_salsa20` | Black Ops II | the exe (`t6mp.exe`, `t6zm.exe` or `t6sp.exe`): its SteamStub code section decrypted, then the 32 bytes the code stores before `DB_SetKey` |
| `codol_rsa`, `codol_file_aes` | Call of Duty Online | `codoMP_client_shipRetail.exe`: the RSA private key, and the file key sealed with it beside it |
| `s2_rsa_private` | WWII | not in the game's files (its exe keeps it encrypted): downloaded once from [Scobalula/s2_ff_killer](https://github.com/Scobalula/s2_ff_killer) at a pinned commit |

- **The install** is found from the file being read: its folder, or the first one above it that
  holds the game's exe. A fast file copied elsewhere needs the game's folder:
  `Context::Install`.
- **Checked**: each key against its SHA-256 (Wolff keeps hashes, never key bytes); a key whose
  hash differs (a game update) is kept only if it opens what it should (a Black Ops II block
  inflates; the CODOL key pair agrees and opens its seal). WWII's must match its hash.
- **Cache**: `%LOCALAPPDATA%\wolff\keys.json`, one entry per key and exe, used while the exe keeps
  its size and last write time (an update finds the key again). It holds the keys: it is yours,
  do not share it.
- **Network**: only WWII's key, once (WinHTTP, HTTPS to raw.githubusercontent.com). To turn it off:
  `Ctx.KeySearch.Network = false`; WWII's signed fast files then fail with an error saying so
  (unless the key is already cached or given by a provider).

```cpp
wolff::Context Ctx;                                  // finds keys itself, default Oodle loader
Ctx.Install = "D:/Games/CODOL";                      // when the file is not under the install
Ctx.KeySearch.Network = false;                       // never download WWII's key
Ctx.KeySearch.CacheFile = "C:/my-tool/keys.json";    // or UseCache = false
wolff::FastFile::Decompress(Path, Zone, Error, Ctx);
```

A `wolff::KeyProvider` is an optional override, asked before all of this: give the keys you
already have (by id, `wolff::keys`) and Wolff looks for the rest.

```cpp
wolff::CallbackKeyProvider Mine([](std::string_view Id, std::vector<uint8_t>& Out) {
    if (Id != wolff::keys::S2RsaPrivate) return false;
    Out = ReadFile("s2_key.der");                    // a PKCS#1 DER private key
    return true;
});
wolff::SetDefaultContext({ &Mine, nullptr });        // nullptr: the default Oodle loader
```

`wolff/Keys.h` exposes the finders directly (`FindKey`, `FindKeyInstall`, `DefaultKeyCacheFile`).

## Oodle

Oodle cannot be redistributed: Wolff loads the games' own `oo2core_*_win64.dll` (6 for Black Ops
4, 8 for Cold War and the `IWffa100` titles, 7) at run time, from the exe's folder and the
search directories you give, each with up to three parent folders:

```cpp
wolff::OodleDllLoader Oodle({ "C:/Games/Call of Duty Black Ops 4" });
wolff::SetDefaultContext({ nullptr, &Oodle });
```

## Zone tables

`wolff/ZoneTables.h` walks a decompressed zone with a zonekit profile: every read the game's loader
does, which asset each belongs to and, with a layout, where each asset instance and pointer is
(`wolff/ZoneLinks.h` resolves the pointers). The profiles ship with Wolff (`profiles/<game>`:
`profile.json`, `types.json`, the reader tables), one per title: t4, t5, t6, t7, bo4, t9, iw3, iw4,
iw5, iw6, iw7, iw8, s1, s2, h1, mwiii, mwiii_sp, bo6, bo6sp, bo7, codol. They are found in
`%WOLFF_PROFILES%`, then `<exe>\wolff\profiles`, `<exe>\profiles`, then where the package installed
them (`share/wolff/profiles`); `ZoneTables::SetProfileRoots` replaces that list.

The newer titles' string cipher tables (`profiles/<game>/strings.cipher.txt`) are not in the
repository.

## Indexes

Two files a full walk can leave behind, so the next read of a few assets skips most of the work.
Each sits in a folder you give (Wolff picks none) and is keyed so a stale one is never read.

- **Resume index** (`wolff/ResumeIndex.h`, `<zone>_<key>.gwr`, about 13 bytes an asset): each
  zone-level asset's resume point (where its walk starts, the stream cursors there) and each named
  asset's point, plus Black Ops 6/7's keys and hashes. `ZoneResume::Find` gives an asset's point, from
  which `ZoneTables::PartialWalk` walks it alone. The key covers the tables and the source files
  (path, size, time written) or the zone's bytes.
- **Install index** (`wolff/InstallIndex.h`, `.gwi`, read in place): which zones of an install
  define each asset, and hold each part (a type and a hash). It answers which zone to open for a
  dependency. `BuildZones` builds it with a pool of workers over your own zone reader, and resumes from
  its partial file when stopped.

An asset is named by type and name. The types are a `TypeList` (an id is a place in the list),
by default the profile's `TypeNames`. The files store only the ids, so you read a file with the list
it was written with.

```cpp
wolff::InstallIndex Install;
Install.SetZones({ "mp_raid.ff" });
wolff::ZoneTables::IndexOptions Ix;
Ix.ResumeFile = wolff::ResumeIndex::FileFor("C:/my-tool/resume", Path, Profile.Name, std::vector<std::string>{ Path });
Ix.Install = &Install;                 // its assets added as zone 0's
auto R = wolff::ZoneTables::WalkZone(Zone, Tables, Profile.TypeNames, Profile.Rules, Ix);
Install.SaveMapped("C:/my-tool/raid.gwi", "my key");
```

By default the walk names each asset by the first string its walk read (`NamedByFirstString`),
which is the name for most asset types but not for Black Ops 6/7's, named by hash. `IndexOptions::Name`
names them your way instead. `ResumeIndex::FromWalk` builds the same index from a walk you already
have.

## Using it

Through vcpkg (an overlay port until Wolff is in the registry: GrayWolf's
`vcpkg-overlay-ports/wolff`):

```
vcpkg install wolff --triplet x64-windows-static-md --overlay-ports=<path>/vcpkg-overlay-ports
```

```cmake
find_package(wolff CONFIG REQUIRED)
target_link_libraries(main PRIVATE wolff::wolff)
```

From source: CMake with vcpkg for the dependencies (`libdeflate`, `lz4`, `miniz`, `casclib` with
`CASC_UNICODE`, `nlohmann-json`, `zydis`), triplet `x64-windows-static-md`:

```
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake -DVCPKG_TARGET_TRIPLET=x64-windows-static-md
cmake --build build --config Release
```

`build/Release/wolff-decompress.exe <fastfile> [<zone out>] [--install <dir>] [--oodle-dir <dir>]
[--no-network] [--no-cache] [--cache <file>]` checks a file.

## License and credits

GPL-3.0 (LICENSE): a program that links Wolff is a work based on it, and is distributed under the
GPL-3.0 too. Formats and code after: Laupetin/OpenAssetTools (GPL-3.0), ate47/atian-cod-tools
(GPL-3.0 or MIT), Joelrau/x64-zt, Scobalula's Greyhound and s2_ff_killer, dtzxporter's WraithXOL
(MIT), google/open-vcdiff (Apache License 2.0, the VCDIFF decoder), atom0s' Steamless (the
SteamStub 3.1 layout). Zydis (MIT) decodes x86.
