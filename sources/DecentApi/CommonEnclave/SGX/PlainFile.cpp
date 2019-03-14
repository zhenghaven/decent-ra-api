#include "../Tools/PlainFile.h"

#include "../../Common/SGX/RuntimeError.h"
#include "edl_decent_file_system.h"

using namespace Decent::Tools;

#define THROW_FILE_NOT_OPENED_EXCEPTION throw FileException("Specified file is not opened yet!")

PlainFile::PlainFile(const std::string & path, const Mode mode) :
	PlainFile(path, mode, sk_deferOpen)
{
	Open();
}

PlainFile::PlainFile(const std::string & path, const Mode mode, DeferOpen) :
	PlainFile(path, FileBase::InterpretMode(mode))
{
}

PlainFile::PlainFile(PlainFile && rhs) :
	m_path(std::move(rhs.m_path)),
	m_modeChar(rhs.m_modeChar),
	m_file(rhs.m_file)
{
	rhs.m_file = nullptr;
}

PlainFile::~PlainFile()
{
	if (IsOpen())
	{
		int retVal = 0;
		ocall_decent_tools_fclose(&retVal, m_file); //Just close it, there is nothing we can do to the error.
		m_file = nullptr;
	}
}

void PlainFile::Open()
{
	sgx_status_t encRet = ocall_decent_tools_fopen(&m_file, m_path.c_str(), m_modeChar);
	DECENT_CHECK_SGX_STATUS_ERROR(encRet, ocall_decent_tools_fopen);

	if (!IsOpen())
	{
		throw FileException("Could not open the specific file! (path = " + m_path + ")");
	}
}

int PlainFile::FSeek(const int64_t pos)
{
	return FSeek(pos, DECENT_FS_SEEK_SET);
}

static int OcallFseek(void* file, int64_t pos, int ori)
{
	int retVal = 0;
	DECENT_CHECK_SGX_STATUS_ERROR(ocall_decent_tools_fseek(& retVal, file, pos, ori), ocall_decent_tools_fseek);
	return retVal;
}

int PlainFile::FSeek(const int64_t pos, const int origin)
{
	return IsOpen() ? OcallFseek(m_file, pos, origin) : THROW_FILE_NOT_OPENED_EXCEPTION;
}

static size_t OcalllFtell(void* file)
{
	size_t retVal = 0;
	DECENT_CHECK_SGX_STATUS_ERROR(ocall_decent_tools_ftell(&retVal, file), ocall_decent_tools_ftell);
	return retVal;
}

size_t PlainFile::FTell() const
{
	return IsOpen() ? OcalllFtell(m_file) : THROW_FILE_NOT_OPENED_EXCEPTION;
}

PlainFile::PlainFile(const std::string & path, const char * modeStr) :
	m_path(path),
	m_modeChar(modeStr),
	m_file(nullptr)
{
}

static size_t OcallFread(void* buffer, size_t bufferSize, void* file)
{
	size_t retVal = 0;
	DECENT_CHECK_SGX_STATUS_ERROR(ocall_decent_tools_fread(&retVal, buffer, bufferSize, file), ocall_decent_tools_fread);
	return retVal;
}

size_t PlainFile::ReadBlockRaw(void * buffer, const size_t size)
{
	return IsOpen() ? OcallFread(buffer, size, m_file) : THROW_FILE_NOT_OPENED_EXCEPTION;
}

WritablePlainFile::WritablePlainFile(const std::string & path, const WritableMode mode) :
	WritablePlainFile(path, mode, sk_deferOpen)
{
	Open();
}

WritablePlainFile::WritablePlainFile(const std::string & path, const WritableMode mode, DeferOpen) :
	PlainFile(path, WritableFileBase::InterpretMode(mode))
{
}

WritablePlainFile::WritablePlainFile(WritablePlainFile && rhs) :
	PlainFile(std::forward<PlainFile>(rhs))
{
}

WritablePlainFile::~WritablePlainFile()
{
}

static int OcallFflush(void* file)
{
	int retVal = 0;
	DECENT_CHECK_SGX_STATUS_ERROR(ocall_decent_tools_fflush(&retVal, file), ocall_decent_tools_fflush);
	return retVal;
}

void WritablePlainFile::FFlush()
{
	int res = IsOpen() ? OcallFflush(GetFilePtr()) : THROW_FILE_NOT_OPENED_EXCEPTION;
}

static size_t OcallFwrite(const void* buffer, size_t bufferSize, void* file)
{
	size_t retVal = 0;
	DECENT_CHECK_SGX_STATUS_ERROR(ocall_decent_tools_fwrite(&retVal, buffer, bufferSize, file), ocall_decent_tools_fwrite);
	return retVal;
}

size_t WritablePlainFile::WriteBlockRaw(const void * buffer, const size_t size)
{
	return IsOpen() ? OcallFwrite(buffer, size, GetFilePtr()) : THROW_FILE_NOT_OPENED_EXCEPTION;
}
