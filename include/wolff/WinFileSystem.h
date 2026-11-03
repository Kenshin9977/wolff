#pragma once
#include <wolff/FileSystem.h>

#include <cstdint>
#include <functional>
#include <string>

namespace wolff
{
class WinFileSystem : public CoDFileSystem
{
public:
	WinFileSystem(const std::string& directory);
	~WinFileSystem();
	virtual HANDLE OpenFile(const std::string& fileName, const std::string& mode);
	virtual void CloseHandle(HANDLE handle);
	virtual bool Exists(const std::string& fileName);
	virtual size_t Read(HANDLE handle, uint8_t* buffer, const size_t offset, const size_t size);
	virtual size_t Write(HANDLE handle, const uint8_t* buffer, const size_t offset, const size_t size);
	virtual size_t Tell(HANDLE handle);
	virtual size_t Seek(HANDLE handle, size_t position, size_t direction);
	virtual size_t Size(HANDLE handle);
	virtual size_t EnumerateFiles(const std::string& pattern, std::function<void(const std::string&, const size_t)> onFileFound);
};
}
