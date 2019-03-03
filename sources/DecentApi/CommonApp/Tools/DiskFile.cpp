#include "DiskFile.h"

#include <cstdio>

#ifdef _WIN32
#include <ShlObj.h>
#include <wchar.h>
#else

#endif // _WIN32

#include <boost/filesystem.hpp>

using namespace Decent::Tools;

DiskFile::DiskFile(const boost::filesystem::path & filePath, const Mode mode, DeferOpen) :
	DiskFile(filePath, DiskFile::GenericInterpretMode(mode))
{
}

DiskFile::DiskFile(const boost::filesystem::path & filePath, const Mode mode) :
	DiskFile(filePath, mode, sk_deferOpen)
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
#ifdef _WIN32
	m_file = _wfopen(m_filePath->c_str(), m_fileModeStr);
#else
	m_file = std::fopen(m_filePath->c_str(), m_fileModeStr);
#endif
	if (!IsOpen())
	{
		throw FileException("Could not open the specific file! (path = " + GetFilePathStr() + ")");
	}
}

int DiskFile::FSeek(const size_t pos)
{
	return FSeek(pos, SEEK_SET);
}

#define THROW_FILE_NOT_OPENED_EXCEPTION throw FileException("Specified file is not opened yet!")

int DiskFile::FSeek(const size_t pos, const int origin)
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

void DiskFile::FFlush()
{
	int res = IsOpen() ? std::fflush(m_file) : THROW_FILE_NOT_OPENED_EXCEPTION;
}

size_t DiskFile::GetFileSize()
{
	const size_t tmp = FTell();
	FSeek(0, SEEK_END);
	const size_t res = FTell();
	FSeek(tmp);
	return res;
}

DiskFile::DiskFile(const boost::filesystem::path & filePath, ConstCharType modeStr) :
	m_filePath(std::make_unique<boost::filesystem::path>(filePath)),
	m_file(nullptr),
	m_fileModeStr(modeStr)
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

WritableDiskFile::WritableDiskFile(const boost::filesystem::path & filePath, const WritableMode mode, DeferOpen) :
	DiskFile(filePath, WritableDiskFile::GenericInterpretMode(mode))
{
}

WritableDiskFile::WritableDiskFile(const boost::filesystem::path & filePath, const WritableMode mode) :
	WritableDiskFile(filePath, mode, sk_deferOpen)
{
	Open();
}

WritableDiskFile::WritableDiskFile(WritableDiskFile && rhs) :
	DiskFile(std::forward<WritableDiskFile>(rhs))
{}

WritableDiskFile::~WritableDiskFile()
{
}

size_t WritableDiskFile::WriteBlockRaw(const void * buffer, const size_t size)
{
	return IsOpen() ? std::fwrite(buffer, sizeof(uint8_t), size, GetFilePtr()) : THROW_FILE_NOT_OPENED_EXCEPTION;
}
