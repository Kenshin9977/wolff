// The default Oodle provider: the games' own oo2core DLLs loaded at run time (Wolff never ships
// one). Grown out of GrayWolf's Siren (after Scobalula's Greyhound), one slot per DLL name rather
// than one for the process: Black Ops 4's oo2core_6 and Cold War's oo2core_8 both stay loaded.

#include <wolff/Context.h>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#include <format>

namespace
{
    // OodleLZ_Decompress, x64 (verified for Oodle 5 to 9; the callbacks are unused)
    using OodleLZ64_DecompressDef = int64_t (*)(unsigned char* Buffer, int64_t BufferSize, unsigned char* OutputBuffer, int64_t OutputBufferSize,
                                                int32_t a, int32_t b, int64_t c, void* d, void* e, void* f, void* g, void* h, void* i,
                                                int32_t ThreadModule);

    std::wstring Wide(std::string_view S)
    {
        return std::wstring(S.begin(), S.end());   // the DLL names are ASCII
    }
}

namespace wolff
{
    struct OodleDllLoader::Library final : OodleDecompressor
    {
        std::string Name;
        HMODULE Module = nullptr;
        OodleLZ64_DecompressDef Decode = nullptr;

        size_t Decompress(const uint8_t* In, size_t InSize, uint8_t* Out, size_t OutSize) const override
        {
            if (Decode == nullptr || In == nullptr || InSize == 0 || Out == nullptr || OutSize == 0)
                return 0;
            // Oodle's last argument is its ThreadPhase: 3 (ThreadPhaseAll) makes Oodle use its own
            // internal threads, which races its phase state when several of the caller's threads decode
            // at once ("corruption: inconsistency detected during phase 2"). 0 (Unthreaded): the
            // containers supply the parallelism.
            const int64_t Result = Decode(const_cast<uint8_t*>(In), (int64_t)InSize, Out, (int64_t)OutSize, 0, 0, 0, nullptr, nullptr, nullptr,
                                          nullptr, nullptr, nullptr, 0);
            return Result > 0 ? (size_t)Result : 0;
        }
    };

    OodleDllLoader::OodleDllLoader() = default;

    OodleDllLoader::OodleDllLoader(std::vector<std::filesystem::path> SearchDirs)
    {
        for (const auto& D : SearchDirs)
            AddSearchDir(D);
    }

    OodleDllLoader::~OodleDllLoader()
    {
        for (const auto& L : Loaded)
            if (L->Module != nullptr) FreeLibrary(L->Module);
    }

    void OodleDllLoader::AddSearchDir(const std::filesystem::path& Dir)
    {
        if (Dir.empty()) return;
        std::error_code Ec;
        auto Abs = std::filesystem::absolute(Dir, Ec);
        if (Ec) return;
        std::lock_guard<std::mutex> Guard(Lock);
        for (const auto& D : Dirs)
            if (D == Abs) return;
        Dirs.push_back(std::move(Abs));
    }

    const OodleDecompressor* OodleDllLoader::Find(std::string_view Name)
    {
        std::lock_guard<std::mutex> Guard(Lock);
        for (const auto& L : Loaded)
            if (L->Name == Name) return L.get();

        // the system's search first (beside the exe), then each directory and up to three parents
        const std::wstring File = Wide(Name);
        HMODULE H = LoadLibraryW(File.c_str());
        if (H == nullptr && !std::filesystem::path(File).has_parent_path())
            for (const auto& Dir : Dirs)
            {
                std::filesystem::path At = Dir;
                for (int Up = 0; Up < 4 && !At.empty() && H == nullptr; Up++, At = At.parent_path())
                {
                    std::error_code Ec;
                    const auto Candidate = At / File;
                    if (std::filesystem::is_regular_file(Candidate, Ec))
                        H = LoadLibraryExW(Candidate.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
                    if (At == At.parent_path()) break;
                }
                if (H != nullptr) break;
            }
        if (H == nullptr) return nullptr;
        auto Decode = (OodleLZ64_DecompressDef)GetProcAddress(H, "OodleLZ_Decompress");
        if (Decode == nullptr)
        {
            FreeLibrary(H);
            return nullptr;
        }
        auto L = std::make_unique<Library>();
        L->Name = std::string(Name);
        L->Module = H;
        L->Decode = Decode;
        Loaded.push_back(std::move(L));
        return Loaded.back().get();
    }

    const OodleDecompressor* GetOodle(const Context& Ctx, std::string_view Name, std::string_view Title, std::string& Error)
    {
        OodleProvider* P = Ctx.Oodle != nullptr ? Ctx.Oodle : DefaultContext().Oodle;
        const OodleDecompressor* D = P != nullptr ? P->Find(Name) : nullptr;
        if (D == nullptr)
            Error = std::format("{} need {}: it is in neither the game's folder nor beside the program", Title, Name);
        return D;
    }
}
