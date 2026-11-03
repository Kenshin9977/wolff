cmake_minimum_required(VERSION 3.21)

project(wolff VERSION 0.1.0 LANGUAGES CXX DESCRIPTION "Call of Duty fast file reader")

if(NOT WIN32)
    message(FATAL_ERROR "Wolff reads with the Windows API (CNG, file mappings, LoadLibrary): Windows only")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(libdeflate CONFIG REQUIRED)
find_package(lz4 CONFIG REQUIRED)
find_package(miniz CONFIG REQUIRED)
find_package(CascLib CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(zydis CONFIG REQUIRED)
# xxHash's header alone (XXH_INLINE_ALL): the indexes' hashes
find_path(XXHASH_INCLUDE_DIR xxhash.h REQUIRED)

add_library(wolff STATIC
    src/Builtins.cpp
    src/CascFileSystem.cpp
    src/Codol.FileCrypt.cpp
    src/Codol.Ifs.cpp
    src/Codol.SealedFastFile.cpp
    src/Compression.cpp
    src/Context.cpp
    src/FastFile.cpp
    src/FastFile.InfinityWard.cpp
    src/FastFile.Sledgehammer.cpp
    src/FastFile.T9.cpp
    src/FastFile.Treyarch.cpp
    src/FileSystem.cpp
    src/Games.cpp
    src/Iw7.cpp
    src/InstallIndex.cpp
    src/Iwff.cpp
    src/KeyFinders.cpp
    src/Keys.cpp
    src/Oodle.cpp
    src/Packages.cpp
    src/ResumeIndex.cpp
    src/Salsa20.cpp
    src/SHA1.cpp
    src/VCDiff.cpp
    src/WinFileSystem.cpp
    src/WorldWar2.cpp
    src/ZoneMemory.cpp
    src/ZoneFormats.cpp
    src/ZoneLinks.cpp
    src/ZoneTableWalker.cpp
    src/formats/CODOL.cpp
    src/formats/IW3.cpp
    src/formats/IW4.cpp
    src/formats/IW6.cpp
    src/formats/IW7.cpp
    src/formats/IW8.cpp
    src/formats/Iwctx.cpp
    src/formats/S1.cpp
    src/formats/S2.cpp
    src/formats/T4.cpp
    src/formats/T5.cpp
    src/formats/T6.cpp
    src/formats/T7.cpp
    src/formats/T8.cpp
    src/formats/T9.cpp
)
add_library(wolff::wolff ALIAS wolff)

target_include_directories(wolff
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${XXHASH_INCLUDE_DIR}
)
target_compile_features(wolff PUBLIC cxx_std_20)
# CascLib's headers declare wide paths (CASCLIB_UNICODE), as the CascLib overlay port builds it
target_compile_definitions(wolff PRIVATE UNICODE _UNICODE NOMINMAX)
if(MSVC)
    target_compile_options(wolff PRIVATE /W3 /utf-8 /permissive- /Zc:__cplusplus)
endif()
# Where the walker looks for the bundled profiles after the exe's folder (DefaultProfileRoots): the
# installed share/wolff/profiles (the vcpkg port passes its installed tree's)
set(WOLFF_INSTALLED_PROFILES "${CMAKE_INSTALL_PREFIX}/share/wolff/profiles" CACHE STRING "Where the installed profiles are read from")
target_compile_definitions(wolff PRIVATE "WOLFF_INSTALLED_PROFILES=\"${WOLFF_INSTALLED_PROFILES}\"")

target_link_libraries(wolff
    PRIVATE
        $<IF:$<TARGET_EXISTS:libdeflate::libdeflate_shared>,libdeflate::libdeflate_shared,libdeflate::libdeflate_static>
        $<IF:$<TARGET_EXISTS:LZ4::lz4>,LZ4::lz4,LZ4::lz4_static>
        miniz::miniz
        nlohmann_json::nlohmann_json
        Zydis::Zydis
        $<IF:$<TARGET_EXISTS:CascLib::casc>,CascLib::casc,CascLib::casc_static>
        bcrypt
        crypt32
        shlwapi
        winhttp
)

option(WOLFF_BUILD_TOOLS "Build wolff-decompress (a command line check)" ${PROJECT_IS_TOP_LEVEL})
if(WOLFF_BUILD_TOOLS)
    add_executable(wolff-decompress tools/wolff_decompress.cpp)
    target_link_libraries(wolff-decompress PRIVATE wolff::wolff)
endif()

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

install(TARGETS wolff EXPORT wolffTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(DIRECTORY include/wolff DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
# The zonekit profiles the walker reads (ZoneTables.h): what a reader needs, not the tools' own
# files (samples, proven lists) nor a machine's profile.local.json
option(WOLFF_INSTALL_PROFILES "Install the zonekit profiles to share/wolff/profiles" ON)
if(WOLFF_INSTALL_PROFILES)
    install(DIRECTORY profiles/ DESTINATION ${CMAKE_INSTALL_DATADIR}/wolff/profiles
        FILES_MATCHING
            PATTERN "*.json"
            PATTERN "*.jsonc"
            PATTERN "tables.*.txt"
            PATTERN "blocks.txt"
            PATTERN "empties.txt"
            PATTERN "shading.txt"
            PATTERN "strings.cipher.txt"
            PATTERN "profile.local*.json" EXCLUDE
            PATTERN "_template" EXCLUDE
    )
endif()
install(EXPORT wolffTargets NAMESPACE wolff:: DESTINATION ${CMAKE_INSTALL_DATADIR}/wolff)

configure_package_config_file(cmake/wolffConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/wolffConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_DATADIR}/wolff
)
write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/wolffConfigVersion.cmake COMPATIBILITY SameMinorVersion)
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/wolffConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/wolffConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_DATADIR}/wolff
)
