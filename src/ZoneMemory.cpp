#include <wolff/ZoneBytes.h>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#include <atomic>
#include <cstring>
#include <condition_variable>
#include <deque>
#include <map>
#include <mutex>
#include <thread>

namespace
{
    // each section a buffer is held in, by the address its view starts at
    struct Section
    {
        HANDLE Mapping = nullptr;
        size_t Bytes = 0;
    };
    std::mutex Lock;
    std::map<const void*, Section> Sections;

    // the section whose view starts at P and holds at least N bytes, nullptr when none
    HANDLE SectionOf(const void* P, size_t N)
    {
        const std::lock_guard<std::mutex> Hold(Lock);
        const auto It = Sections.find(P);
        return It != Sections.end() && It->second.Bytes >= N ? It->second.Mapping : nullptr;
    }

    // the bytes of the sections not torn down yet (held, or freed and waiting for the unmapping
    // thread), and the most there were
    std::atomic<uint64_t> HeldBytes{ 0 }, PeakBytes{ 0 };

    void TearDown(void* View, HANDLE Mapping, size_t Bytes)
    {
        UnmapViewOfFile(View);
        if (Mapping != nullptr) CloseHandle(Mapping);
        HeldBytes -= Bytes;
    }

    // A section freed torn down on a thread of its own when no other waits there: one zone's close
    // (hundreds of MB of pages, ~150 ms for 650 MB) does not wait on it. A section freed while one
    // is still waiting is torn down by the thread freeing it: zones read side by side by several
    // workers, each freeing ~2 GB a second (a patched zone frees its base, its delta and its
    // target), outran the one thread (17 GB held after MWIII's 596 zones on 8 workers); now what is
    // held is what is alive, and at most one section more. Never destroyed (the process may end
    // with one queued: the system unmaps it).
    class Unmapping
    {
    public:
        Unmapping()
        {
            std::thread([this] {
                for (;;)
                {
                    Pending Next;
                    {
                        std::unique_lock<std::mutex> Hold(QueueLock);
                        Ready.wait(Hold, [this] { return Waiting.View != nullptr; });
                        Next = Waiting;
                    }
                    TearDown(Next.View, Next.Mapping, Next.Bytes);
                    // (free again only once torn down: one section at a time waits here)
                    const std::lock_guard<std::mutex> Hold(QueueLock);
                    Waiting = Pending();
                }
            }).detach();
        }
        // false when another waits: the caller tears it down
        bool Push(void* View, HANDLE Mapping, size_t Bytes)
        {
            {
                const std::lock_guard<std::mutex> Hold(QueueLock);
                if (Waiting.View != nullptr) return false;
                Waiting = { View, Mapping, Bytes };
            }
            Ready.notify_one();
            return true;
        }

    private:
        struct Pending
        {
            void* View = nullptr;
            HANDLE Mapping = nullptr;
            size_t Bytes = 0;
        };
        std::mutex QueueLock;
        std::condition_variable Ready;
        Pending Waiting;
    };
    Unmapping& Unmapper()
    {
        static Unmapping* U = new Unmapping();
        return *U;
    }
}

namespace wolff::ZoneMemory
{
    void* Allocate(size_t Bytes)
    {
        if (Bytes < SectionFrom) return ::operator new(Bytes);
        const uint64_t Size = Bytes;
        HANDLE M = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE | SEC_COMMIT, (DWORD)(Size >> 32), (DWORD)Size, nullptr);
        if (M == nullptr) throw std::bad_alloc();
        void* P = MapViewOfFile(M, FILE_MAP_WRITE, 0, 0, Bytes);
        if (P == nullptr)
        {
            CloseHandle(M);
            throw std::bad_alloc();
        }
        {
            const std::lock_guard<std::mutex> Hold(Lock);
            Sections[P] = { M, Bytes };
        }
        const uint64_t Now = HeldBytes += Bytes;
        for (uint64_t Was = PeakBytes.load(); Now > Was && !PeakBytes.compare_exchange_weak(Was, Now);) {}
        return P;
    }

    Usage Held()
    {
        return { HeldBytes.load(), PeakBytes.load() };
    }

    void Free(void* P, size_t Bytes)
    {
        if (P == nullptr) return;
        if (Bytes < SectionFrom)
        {
            ::operator delete(P);
            return;
        }
        HANDLE M = nullptr;
        size_t Size = 0;
        {
            const std::lock_guard<std::mutex> Hold(Lock);
            const auto It = Sections.find(P);
            if (It != Sections.end())
            {
                M = It->second.Mapping;
                Size = It->second.Bytes;
                Sections.erase(It);
            }
        }
        // (a copy-on-write view of it keeps the section alive until that view is unmapped)
        if (!Unmapper().Push(P, M, Size)) TearDown(P, M, Size);
    }

    Copy::Copy(ByteView From)
    {
        if (HANDLE M = SectionOf(From.data(), From.size()); M != nullptr && !From.empty())
            if (void* V = MapViewOfFile(M, FILE_MAP_COPY, 0, 0, From.size()); V != nullptr)
            {
                View = V;
                Data = static_cast<uint8_t*>(V);
                Size = From.size();
                return;
            }
        Owned.assign(From.begin(), From.end());
        Data = Owned.data();
        Size = Owned.size();
    }

    Copy::Copy(std::vector<uint8_t> Bytes) : Owned(std::move(Bytes))
    {
        Data = Owned.data();
        Size = Owned.size();
    }

    Copy::~Copy() { Clear(); }

    Copy::Copy(Copy&& O) noexcept { *this = std::move(O); }

    Copy& Copy::operator=(Copy&& O) noexcept
    {
        if (this == &O) return *this;
        Clear();
        const bool Mine = O.View == nullptr;
        Owned = std::move(O.Owned);
        View = O.View;
        Size = O.Size;
        Data = Mine ? Owned.data() : O.Data;
        O.View = nullptr;
        O.Data = nullptr;
        O.Size = 0;
        return *this;
    }

    void Copy::Clear()
    {
        if (View != nullptr) UnmapViewOfFile(View);
        View = nullptr;
        Owned = {};
        Data = nullptr;
        Size = 0;
    }
}
