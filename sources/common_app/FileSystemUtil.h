#pragma once

#include <cstdint>

#include <vector>

#include <boost/filesystem/path.hpp>

namespace fs = boost::filesystem;

enum class KnownFolderType
{
	WorkingDir,
	LocalAppData,
	LocalAppDataEnclave,
	Temp,
	Home,
	Desktop,
	Documents,
	Downloads,
	Music,
	Pictures,
	Videos,
};

fs::path GetKnownFolderPath(KnownFolderType type);

//class FILE;

class FileHandler
{
public:
	enum class Mode
	{
		Read,
		Write,
		Append,
		ReadUpdate,
		WriteUpdate,
		AppendUpdate,
	};

	FileHandler() =delete;

	FileHandler(const fs::path filePath, const Mode mode);

	bool Open();
	bool IsOpen() const;
	const Mode GetMode() const;

	bool ReadBlock(std::vector<uint8_t>& dest, size_t size);
	bool WriteBlock(const std::vector<uint8_t>& dest);

	int FSeek(size_t pos);
	int FSeek(size_t pos, int origin);
	size_t FTell() const;
	void FFlush();

	size_t GetFileSize();
	fs::path GetFilePath() const;

	~FileHandler();

private:
	const char* InterpretMode(const Mode mode);
	const wchar_t* InterpretModeW(const Mode mode);

	const fs::path m_filePath;
	const Mode m_mode;
	bool m_isWriteAllowed;
	FILE* m_file;
};