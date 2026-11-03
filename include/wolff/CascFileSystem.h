#pragma once
#include <wolff/FileSystem.h>

#include <cstdint>
#include <functional>
#include <string>

namespace wolff
{
class CascFileSystem : public CoDFileSystem
{
private:
	HANDLE StorageHandle;
public:
	CascFileSystem(const std::string& directory);
	~CascFileSystem();
	virtual HANDLE OpenFile(const std::string& fileName, const std::string& mode);
	// Closes the handle only.
	virtual void CloseHandle(HANDLE handle);
	virtual bool Exists(const std::string& fileName);
	virtual size_t Read(HANDLE handle, uint8_t* buffer, const size_t offset, const size_t size);
	virtual size_t Write(HANDLE handle, const uint8_t* buffer, const size_t offset, const size_t size);
	virtual size_t Tell(HANDLE handle);
	virtual size_t Seek(HANDLE handle, size_t position, size_t direction);
	virtual size_t Size(HANDLE handle);
	virtual size_t EnumerateFiles(const std::string& pattern, std::function<void(const std::string&, const size_t)> onFileFound);
	// Same walk, plus each file's content key (hex): files with the same key are one stored copy.
	void EnumerateFilesWithKey(const std::string& pattern, std::function<void(const std::string&, const size_t, const std::string&)> onFileFound);
	// How a file is stored: its encoded (on-disk) size over all spans, and its spans' encoding keys
	// joined by '+' - two files with the same keys are the same stored bytes.
	bool StorageInfo(const std::string& name, uint64_t& contentSize, uint64_t& encodedSize, std::string& spanKeys);
};
}
