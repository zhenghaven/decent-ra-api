#include "DiskFile.h"

#include <cstdio>

#ifdef _WIN32
#include <ShlObj.h>
#include <wchar.h>
#else

#endif // _WIN32

#ifdef __unix__
#include <unistd.h>
#include <fcntl.h>
#include <sys/file.h>
#endif

#include <boost/filesystem.hpp>

using namespace Decent::Tools;

namespace
{
	bool IsReadOnly(const char* mode)
	{
		return mode != nullptr ? (mode[0] == 'r' && mode[1] != '+') :
			throw FileException("nullptr input for file open mode!");
	}

	bool IsReadOnly(const wchar_t* mode)
	{
		return mode != nullptr ? (mode[0] == L'r' && mode[1] != L'+') :
			throw FileException("nullptr input for file open mode!");
	}
}

#ifdef _WIN32
void * DiskFile::FopenExclusive(const wchar_t * filePath, const wchar_t* mode)
{
	return _wfsopen(filePath, mode, IsReadOnly(mode) ? _SH_DENYWR : _SH_DENYRW);
}

void * DiskFile::FopenExclusive(const char * filePath, const char* mode)
{
	return _fsopen(filePath, mode, IsReadOnly(mode) ? _SH_DENYWR : _SH_DENYRW);
}
#endif

#ifdef __unix__

namespace
{
	void* fopen_exclusive(const char * filePath, bool isReadOnly, const char* wrMode)
	{
		if (filePath == nullptr || strnlen(filePath, 1) == 0)
		{
			return nullptr;
		}

		mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;

		int fd = open(filePath, (isReadOnly ? O_RDONLY : O_CREAT | O_RDWR) | O_LARGEFILE, mode);
		if (fd == -1)
		{
			return nullptr;
		}
		
		int sysRet = 0;

		sysRet = flock(fd, (isReadOnly ? LOCK_SH : LOCK_EX) | LOCK_NB);
		if (sysRet != 0)
		{
			return nullptr;
		}
		
		void* res = fdopen(fd, wrMode);
		if (res == nullptr)
		{
			flock(fd, LOCK_UN);
		}

		return res;
	}
}

void * DiskFile::FopenExclusive(const char * filePath, const char* mode)
{
	return fopen_exclusive(filePath, IsReadOnly(mode), mode);
}

#endif

DiskFile::DiskFile(const boost::filesystem::path & filePath, const Mode mode, bool isExclusive, DeferOpen) :
	DiskFile(filePath, DiskFile::GenericInterpretMode(mode), isExclusive)
{
}

DiskFile::DiskFile(const boost::filesystem::path & filePath, const Mode mode, bool isExclusive) :
	DiskFile(filePath, mode, isExclusive, sk_deferOpen)
{
	Open();
}

DiskFile::DiskFile(DiskFile && rhs) :
	m_filePath(std::forward<std::unique_ptr<boost::filesystem::path> >(rhs.m_filePath)),
	m_file(rhs.m_file),
	m_fileModeStr(rhs.m_fileModeStr)
{
	rhs.m_file = nullptr;
	rhs.m_fileModeStr = nullptr;
}

DiskFile::~DiskFile()
{
	if (IsOpen())
	{
		std::fclose(m_file);
		m_file = nullptr;
	}
	m_filePath.reset();
}

void DiskFile::Open()
{
	if (m_isExclusive)
	{
		m_file = static_cast<FILE*>(FopenExclusive(m_filePath->c_str(), m_fileModeStr));
	}
	else
	{
#ifdef _WIN32
		m_file = _wfopen(m_filePath->c_str(), m_fileModeStr);
#else
		m_file = std::fopen(m_filePath->c_str(), m_fileModeStr);
#endif
	}

	if (!IsOpen())
	{
		throw FileException("Could not open the specific file! (path = " + GetFilePathStr() + ")");
	}
}

int DiskFile::FSeek(const int64_t pos)
{
	return FSeek(pos, SEEK_SET);
}

#define THROW_FILE_NOT_OPENED_EXCEPTION throw FileException("Specified file is not opened yet!")

int DiskFile::FSeek(const int64_t pos, const int origin)
{
#ifdef __CYGWIN__
	return IsOpen() ? std::fseek(m_file, pos, origin) : THROW_FILE_NOT_OPENED_EXCEPTION;
#elif defined (_WIN32)
	return IsOpen() ? _fseeki64(m_file, pos, origin) : THROW_FILE_NOT_OPENED_EXCEPTION;
#else
	return IsOpen() ? fseeko64(m_file, pos, origin) : THROW_FILE_NOT_OPENED_EXCEPTION;
#endif
}

size_t DiskFile::FTell() const
{
#ifdef __CYGWIN__
	return IsOpen() ? std::ftell(m_file) : THROW_FILE_NOT_OPENED_EXCEPTION;
#elif defined (_WIN32)
	return IsOpen() ? _ftelli64(m_file) : THROW_FILE_NOT_OPENED_EXCEPTION;
#else
	return IsOpen() ? ftello64(m_file) : THROW_FILE_NOT_OPENED_EXCEPTION;
#endif
}

DiskFile::DiskFile(const boost::filesystem::path & filePath, ConstCharType modeStr, bool isExclusive) :
	m_filePath(std::make_unique<boost::filesystem::path>(filePath)),
	m_file(nullptr),
	m_fileModeStr(modeStr),
	m_isExclusive(isExclusive)
{
}

size_t DiskFile::ReadBlockRaw(void * buffer, const size_t size)
{
	return IsOpen() ? std::fread(buffer, sizeof(uint8_t), size, m_file) : THROW_FILE_NOT_OPENED_EXCEPTION;
}

std::string DiskFile::GetFilePathStr() const
{
	return m_filePath->generic_string();
}

WritableDiskFile::WritableDiskFile(const boost::filesystem::path & filePath, const WritableMode mode, bool isExclusive, DeferOpen) :
	DiskFile(filePath, WritableDiskFile::GenericInterpretMode(mode), isExclusive)
{
}

WritableDiskFile::WritableDiskFile(const boost::filesystem::path & filePath, const WritableMode mode, bool isExclusive) :
	WritableDiskFile(filePath, mode, isExclusive, sk_deferOpen)
{
	Open();
}

WritableDiskFile::WritableDiskFile(WritableDiskFile && rhs) :
	DiskFile(std::forward<WritableDiskFile>(rhs))
{}

WritableDiskFile::~WritableDiskFile()
{
}

void WritableDiskFile::FFlush()
{
	int res = IsOpen() ? std::fflush(GetFilePtr()) : THROW_FILE_NOT_OPENED_EXCEPTION;
}

size_t WritableDiskFile::WriteBlockRaw(const void * buffer, const size_t size)
{
	return IsOpen() ? std::fwrite(buffer, sizeof(uint8_t), size, GetFilePtr()) : THROW_FILE_NOT_OPENED_EXCEPTION;
}
