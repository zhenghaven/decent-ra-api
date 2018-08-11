#include "SGXEnclaveRuntimeException.h"

SGXEnclaveRuntimeException::SGXEnclaveRuntimeException(sgx_status_t errCode, const std::string & funcName) :
	m_errCode(errCode),
	m_funcName(funcName)
{
}

SGXEnclaveRuntimeException::~SGXEnclaveRuntimeException()
{
}

const char * SGXEnclaveRuntimeException::what() const throw()
{
	return "SGX Enclave Runtime Exception";
}

sgx_status_t SGXEnclaveRuntimeException::GetErrorCode() const
{
	return m_errCode;
}

std::string SGXEnclaveRuntimeException::GetFuncName() const
{
	return m_funcName;
}
