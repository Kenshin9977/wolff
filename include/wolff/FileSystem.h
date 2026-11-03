#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace wolff
{
// A file system a game's files are read from: a folder (WinFileSystem), a Battle.net CASC
// storage (CascFileSystem). (After Scobalula's Greyhound.)
class CoDFileSystem
{
protected:
	std::string Directory;
	size_t LastErrorCode = 0;
	std::vector<HANDLE> OpenHandles;
public:
	virtual HANDLE OpenFile(const std::string& fileName, const std::string& mode) = 0;
	virtual ~CoDFileSystem();
	virtual void CloseFile(HANDLE handle);
	// Closes the handle only.
	virtual void CloseHandle(HANDLE handle) = 0;
	virtual bool Exists(const std::string& fileName) = 0;
	virtual std::unique_ptr<uint8_t[]> Read(HANDLE handle, const size_t size);
	virtual size_t Read(HANDLE handle, uint8_t* buffer, const size_t offset, const size_t size) = 0;
	template <class T>
	T Read(HANDLE handle)
	{
		T r{};
		Read(handle, (uint8_t*)&r, 0, sizeof(r));
		return r;
	}
	virtual size_t Write(HANDLE handle, const uint8_t* buffer, const size_t size);
	virtual size_t Write(HANDLE handle, const uint8_t* buffer, const size_t offset, const size_t size) = 0;
	virtual size_t Tell(HANDLE handle) = 0;
	virtual size_t Seek(HANDLE handle, size_t position, size_t direction) = 0;
	virtual size_t Size(HANDLE handle) = 0;
	virtual size_t EnumerateFiles(const std::string& pattern, std::function<void(const std::string&, const size_t)> onFileFound) = 0;
	const size_t GetLastError() const;
	const bool IsValid() const;
};
}
