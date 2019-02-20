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
	FileBase(mode),
	m_filePath(std::make_unique<boost::filesystem::path>(filePath)),
	m_file(nullptr)
{
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

void Decent::Tools::DiskFile::Open()
{
#ifdef _WIN32
	m_file = _wfopen(m_filePath->c_str(), InterpretModeW(GetMode()));
#else
	m_file = std::fopen(m_filePath->c_str(), InterpretMode(GetMode()));
#endif
	if (!IsOpen())
	{
		throw FileException("Could not open the specific file! (path = " + GetFilePathStr() + ")");
	}
}

int Decent::Tools::DiskFile::FSeek(const size_t pos)
{
	return FSeek(pos, SEEK_SET);
}

int Decent::Tools::DiskFile::FSeek(const size_t pos, const int origin)
{
	if (!IsOpen())
	{
		throw FileException("Specified file is not opened yet!");
	}
#ifdef __CYGWIN__
	return std::fseek(m_file, pos, origin);
#elif defined (_WIN32)
	return _fseeki64(m_file, pos, origin);
#else
	return fseeko64(m_file, pos, origin);
#endif
}

size_t Decent::Tools::DiskFile::FTell() const
{
	if (!IsOpen())
	{
		throw FileException("Specified file is not opened yet!");
	}
#ifdef __CYGWIN__
	return std::ftell(m_file);
#elif defined (_WIN32)
	return _ftelli64(m_file);
#else
	return ftello64(m_file);
#endif
}

void Decent::Tools::DiskFile::FFlush()
{
	if (!IsOpen())
	{
		throw FileException("Specified file is not opened yet!");
	}
	std::fflush(m_file);
}

size_t Decent::Tools::DiskFile::GetFileSize()
{
	const size_t tmp = FTell();
	FSeek(0, SEEK_END);
	const size_t res = FTell();
	FSeek(tmp);
	return res;
}

size_t Decent::Tools::DiskFile::ReadBlockRaw(void * buffer, const size_t size)
{
	return IsOpen() ? std::fread(buffer, sizeof(uint8_t), size, m_file) : throw FileException("Specified file is not opened yet!");
}

size_t Decent::Tools::DiskFile::WriteBlockRaw(const void * buffer, const size_t size)
{
	return IsOpen() && IsWriteAllowed() ? std::fwrite(buffer, sizeof(uint8_t), size, m_file) : throw FileException("Specified file could not be written!");
}

std::string Decent::Tools::DiskFile::GetFilePathStr() const
{
	return m_filePath->generic_string();
}
