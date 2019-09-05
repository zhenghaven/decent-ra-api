//#if ENCLAVE_PLATFORM_SGX

#include "../SecureFile.h"

#include <sgx_tprotected_fs.h>

#include "../../../Common/make_unique.h"

using namespace Decent;
using namespace Decent::Tools;

#define THROW_FILE_NOT_OPENED_EXCEPTION throw FileException("Specified file is not opened yet!")

SecureFile::SecureFile(const std::string & path, std::unique_ptr<G128BitSecretKeyWrap> key, const char * modeStr) :
	m_path(path),
	m_userKey(std::move(key)),
	m_modeChar(modeStr),
	m_file(nullptr)
{
}

SecureFile::SecureFile(const std::string & path, const Mode mode) :
	SecureFile(path, mode, sk_deferOpen)
{
	Open();
}

SecureFile::SecureFile(const std::string & path, const Mode mode, DeferOpen) :
	SecureFile(path, nullptr, FileBase::InterpretMode(mode))
{
}

SecureFile::SecureFile(const std::string & path, const G128BitSecretKeyWrap & key, const Mode mode) :
	SecureFile(path, key, mode, sk_deferOpen)
{
	Open();
}

SecureFile::SecureFile(const std::string & path, const G128BitSecretKeyWrap & key, const Mode mode, DeferOpen) :
	SecureFile(path, Tools::make_unique<G128BitSecretKeyWrap>(key), FileBase::InterpretMode(mode))
{
}

SecureFile::SecureFile(SecureFile && rhs) :
	m_path(std::forward<std::string>(rhs.m_path)),
	m_userKey(std::forward<std::unique_ptr<G128BitSecretKeyWrap> >(rhs.m_userKey)),
	m_modeChar(rhs.m_modeChar),
	m_file(rhs.m_file)
{
	m_file = nullptr;
}

SecureFile::~SecureFile()
{
	if (IsOpen())
	{
		sgx_fclose(static_cast<SGX_FILE*>(m_file));
		m_file = nullptr;
	}
}

void SecureFile::Open()
{
	if (m_userKey)
	{
		m_file = sgx_fopen(m_path.c_str(), m_modeChar, reinterpret_cast<const sgx_key_128bit_t*>(m_userKey->m_key.data()));
	}
	else
	{
		m_file = sgx_fopen_auto_key(m_path.c_str(), m_modeChar);
	}
	if (!IsOpen())
	{
		throw FileException("Could not open the specific file! (path = " + m_path + ")");
	}
}

int SecureFile::FSeek(const int64_t pos)
{
	return FSeek(pos, SEEK_SET);
}

int SecureFile::FSeek(const int64_t pos, const int origin)
{
	return IsOpen() ? static_cast<int>(sgx_fseek(static_cast<SGX_FILE*>(m_file), pos, origin)) : THROW_FILE_NOT_OPENED_EXCEPTION;
}

size_t SecureFile::FTell() const
{
	return IsOpen() ? static_cast<size_t>(sgx_ftell(static_cast<SGX_FILE*>(m_file))) : THROW_FILE_NOT_OPENED_EXCEPTION;
}

size_t SecureFile::ReadBlockRaw(void * buffer, const size_t size)
{
	return IsOpen() ? sgx_fread(buffer, sizeof(uint8_t), size, static_cast<SGX_FILE*>(m_file)) : THROW_FILE_NOT_OPENED_EXCEPTION;
}

WritableSecureFile::WritableSecureFile(const std::string & path, const WritableMode mode) :
	WritableSecureFile(path, mode, sk_deferOpen)
{
	Open();
}

WritableSecureFile::WritableSecureFile(const std::string & path, const WritableMode mode, DeferOpen) :
	SecureFile(path, nullptr, WritableFileBase::InterpretMode(mode))
{
}

WritableSecureFile::WritableSecureFile(const std::string & path, const G128BitSecretKeyWrap & key, const WritableMode mode) :
	WritableSecureFile(path, key, mode, sk_deferOpen)
{
	Open();
}

WritableSecureFile::WritableSecureFile(const std::string & path, const G128BitSecretKeyWrap & key, const WritableMode mode, DeferOpen) :
	SecureFile(path, Tools::make_unique<G128BitSecretKeyWrap>(key), WritableFileBase::InterpretMode(mode))
{
}

WritableSecureFile::WritableSecureFile(WritableSecureFile && rhs) :
	SecureFile(std::forward<SecureFile>(rhs))
{
}

WritableSecureFile::~WritableSecureFile()
{
}

void WritableSecureFile::FFlush()
{
	int res = IsOpen() ? static_cast<int>(sgx_fflush(static_cast<SGX_FILE*>(GetFilePtr()))) : THROW_FILE_NOT_OPENED_EXCEPTION;
}

size_t WritableSecureFile::WriteBlockRaw(const void * buffer, const size_t size)
{
	return IsOpen() ? sgx_fwrite(buffer, sizeof(uint8_t), size, static_cast<SGX_FILE*>(GetFilePtr())) : THROW_FILE_NOT_OPENED_EXCEPTION;
}

//#endif //ENCLAVE_PLATFORM_SGX
