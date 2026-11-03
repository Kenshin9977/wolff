// wolff-decompress <fastfile> [<zone out>] [--oodle-dir <dir>]... [--install <dir>] [--no-network]
//                 [--no-cache] [--cache <file>]
// The fast file identified, its game found, its zone decompressed (keys found by Wolff itself).
// Prints what it found; writes the zone when given a path.

#include <wolff/FastFile.h>
#include <wolff/Games.h>

#include <chrono>
#include <cstdio>
#include <fstream>
#include <string>

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        std::fprintf(stderr, "usage: wolff-decompress <fastfile> [<zone out>] [--oodle-dir <dir>]... [--install <dir>] "
                             "[--no-network] [--no-cache] [--cache <file>]\n");
        return 2;
    }
    wolff::OodleDllLoader Oodle;
    wolff::Context Ctx{ nullptr, &Oodle };
    std::string In = argv[1], Out;
    for (int K = 2; K < argc; K++)
    {
        const std::string A = argv[K];
        if (A == "--oodle-dir" && K + 1 < argc) Oodle.AddSearchDir(argv[++K]);
        else if (A == "--install" && K + 1 < argc) Ctx.Install = argv[++K];
        else if (A == "--cache" && K + 1 < argc) Ctx.KeySearch.CacheFile = argv[++K];
        else if (A == "--no-network") Ctx.KeySearch.Network = false;
        else if (A == "--no-cache") Ctx.KeySearch.UseCache = false;
        else Out = A;
    }
    wolff::RegisterBuiltins();
    const auto Info = wolff::FastFile::Identify(In);
    const auto* Game = wolff::FindGameModule(Info.Magic, Info.Version, In);
    std::printf("magic=%s\nversion=%u\nformat=%d\ngame=%s\n", Info.Magic.c_str(), Info.Version, (int)Info.Format, Game ? Game->Engine : "");
    wolff::ZoneBytes Zone;
    std::string Error;
    const auto Start = std::chrono::steady_clock::now();
    const bool Ok = wolff::FastFile::Decompress(In, Zone, Error, Ctx);
    const double Seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - Start).count();
    if (!Ok)
    {
        std::printf("result=error\nreason=%s\nseconds=%.3f\n", Error.c_str(), Seconds);
        return 1;
    }
    std::printf("result=ok\nzone_bytes=%zu\nseconds=%.3f\n", Zone.size(), Seconds);
    if (!Out.empty())
    {
        std::ofstream F(Out, std::ios::binary | std::ios::trunc);
        F.write(reinterpret_cast<const char*>(Zone.data()), (std::streamsize)Zone.size());
    }
    return 0;
}
