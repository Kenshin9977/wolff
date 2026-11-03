#pragma once

// Wolff: a Call of Duty fast file reader. A fast file in, its zone (decrypted, decompressed, its
// update patch applied) out; which title it belongs to; the archives and storages the files come
// in. GPL-3.0.

#include <wolff/ByteView.h>
#include <wolff/Context.h>
#include <wolff/Keys.h>
#include <wolff/ZoneBytes.h>

#include <wolff/FastFile.h>
#include <wolff/Games.h>
#include <wolff/ZoneAssetTypes.h>

#include <wolff/ZoneFormat.h>
#include <wolff/ZoneLinks.h>
#include <wolff/ZoneTables.h>
#include <wolff/ResumeIndex.h>
#include <wolff/InstallIndex.h>

#include <wolff/Codol.h>
#include <wolff/Iw7.h>
#include <wolff/Iwff.h>
#include <wolff/VCDiff.h>
#include <wolff/WorldWar2.h>

#include <wolff/CascFileSystem.h>
#include <wolff/FileSystem.h>
#include <wolff/Packages.h>
#include <wolff/WinFileSystem.h>
