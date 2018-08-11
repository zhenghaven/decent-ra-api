#include "FileSystemUtil.h"

#include <cstdio>

#ifdef _WIN32
#include <ShlObj.h>
#include <wchar.h>
#else

#endif // _WIN32

fs::path GetKnownFolderPath(KnownFolderType type)
{
	switch (type)
	{
	case KnownFolderType::WorkingDir:
		return fs::path(".");
	case KnownFolderType::Temp:
	{
		const char* tempPath = std::getenv("TEMP");
		const char* tmpPath = std::getenv("TMP");
		if (tempPath)
		{
			return fs::path(tempPath);
		}
		else if (tmpPath)
		{
			return fs::path(tmpPath);
		}
		else
		{
			return fs::path("./~tmp/");
		}
	}
	}
#ifdef _WIN32
	
	KNOWNFOLDERID folderId;
	switch (type)
	{
	case KnownFolderType::LocalAppData:
	case KnownFolderType::LocalAppDataEnclave:
		folderId = FOLDERID_LocalAppData;
		break;
	case KnownFolderType::Home:
		folderId = FOLDERID_Profile;
		break;
	case KnownFolderType::Desktop:
		folderId = FOLDERID_Desktop;
		break;
	case KnownFolderType::Documents:
		folderId = FOLDERID_Documents;
		break;
	case KnownFolderType::Downloads:
		folderId = FOLDERID_Downloads;
		break;
	case KnownFolderType::Music:
		folderId = FOLDERID_Music;
		break;
	case KnownFolderType::Pictures:
		folderId = FOLDERID_Pictures;
		break;
	case KnownFolderType::Videos:
		folderId = FOLDERID_Videos;
		break;
	}
	LPWSTR winPath = NULL;
	HRESULT result = SHGetKnownFolderPath(folderId, 0, NULL, &winPath);
	if (result == S_OK)
	{
		fs::path resPath(winPath);
		CoTaskMemFree(winPath);

		if (type == KnownFolderType::LocalAppDataEnclave)
		{
			resPath.append("EnclaveApps");
		}
		return resPath;
	}
	
#else
	const char* homePath = std::getenv("HOME");
	if (homePath)
	{
		fs::path resPath(homePath);
		switch (type)
		{
		case KnownFolderType::Home:
		case KnownFolderType::LocalAppData:
			break;
		case KnownFolderType::LocalAppDataEnclave:
			resPath.append("EnclaveApps");
			break;
		case KnownFolderType::Desktop:
			resPath.append("Desktop");
			break;
		case KnownFolderType::Documents:
			resPath.append("Documents");
			break;
		case KnownFolderType::Downloads:
			resPath.append("Downloads");
			break;
		case KnownFolderType::Music:
			resPath.append("Music");
			break;
		case KnownFolderType::Pictures:
			resPath.append("Pictures");
			break;
		case KnownFolderType::Videos:
			resPath.append("Videos");
			break;
		}
		return resPath;
	}
#endif // _WIN32
	return fs::path(".");
}

const char* FileHandler::InterpretMode(const Mode mode)
{
	switch (mode)
	{
	case FileHandler::Mode::Read:
		m_isWriteAllowed = false;
		return "rb";
	case FileHandler::Mode::Write:
		m_isWriteAllowed = true;
		return "wb";
	case FileHandler::Mode::Append:
		m_isWriteAllowed = true;
		return "ab";
	case FileHandler::Mode::ReadUpdate:
		m_isWriteAllowed = false;
		return "r+b";
	case FileHandler::Mode::WriteUpdate:
		m_isWriteAllowed = true;
		return "w+b";
	case FileHandler::Mode::AppendUpdate:
		m_isWriteAllowed = true;
		return "a+b";
	default:
		return "rb";
	}
}

const wchar_t * FileHandler::InterpretModeW(const Mode mode)
{
	switch (mode)
	{
	case FileHandler::Mode::Read:
		m_isWriteAllowed = false;
		return L"rb";
	case FileHandler::Mode::Write:
		m_isWriteAllowed = true;
		return L"wb";
	case FileHandler::Mode::Append:
		m_isWriteAllowed = true;
		return L"ab";
	case FileHandler::Mode::ReadUpdate:
		m_isWriteAllowed = false;
		return L"r+b";
	case FileHandler::Mode::WriteUpdate:
		m_isWriteAllowed = true;
		return L"w+b";
	case FileHandler::Mode::AppendUpdate:
		m_isWriteAllowed = true;
		return L"a+b";
	default:
		return L"rb";
	}
}

FileHandler::FileHandler(const fs::path filePath, const Mode mode) : 
	m_filePath(filePath),
	m_mode(mode),
	m_file(nullptr)
{
}

bool FileHandler::Open()
{
#ifdef _WIN32
	m_file = _wfopen(m_filePath.c_str(), InterpretModeW(m_mode));
#else
	m_file = std::fopen(m_filePath.c_str(), InterpretMode(m_mode));
#endif
	return (m_file != nullptr);
}

bool FileHandler::IsOpen() const
{
	return (m_file != nullptr);
}

const FileHandler::Mode FileHandler::GetMode() const
{
	return m_mode;
}

bool FileHandler::ReadBlock(std::vector<uint8_t>& dest, size_t size)
{
	dest.resize(size);
	size_t resSize = std::fread(&dest[0], sizeof(uint8_t), size, m_file);
	dest.resize(resSize);

	return resSize == size;
}

bool FileHandler::WriteBlock(const std::vector<uint8_t>& dest)
{
	size_t resSize = std::fwrite(&dest[0], 1, dest.size(), m_file);
	return resSize == dest.size();
}

int FileHandler::FSeek(size_t pos)
{
	return FSeek(pos, SEEK_SET);
}

int FileHandler::FSeek(size_t pos, int origin)
{
#ifdef __CYGWIN__
	return std::fseek(m_file, pos, origin);
#elif defined (_WIN32)
	return _fseeki64(m_file, pos, origin);
#else
	return fseeko64(m_file, pos, origin);
#endif
}

size_t FileHandler::FTell() const
{
#ifdef __CYGWIN__
	return std::ftell(m_file);
#elif defined (_WIN32)
	return _ftelli64(m_file);
#else
	return ftello64(m_file);
#endif
}

void FileHandler::FFlush()
{
	std::fflush(m_file);
}

size_t FileHandler::GetFileSize()
{
	size_t tmp = FTell();
	FSeek(0, SEEK_END);
	size_t res = FTell();
	FSeek(tmp);
	return res;
}

fs::path FileHandler::GetFilePath() const
{
	return m_filePath;
}

FileHandler::~FileHandler()
{
	if (IsOpen())
	{
		std::fclose(m_file);
		m_file = nullptr;
	}
}