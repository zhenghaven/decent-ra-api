#pragma once

#include "../EnclaveException.h"

#include <string>

#include <sgx_error.h>

#define CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(X, Y) if(X != SGX_SUCCESS) {\
                                                  throw SGXEnclaveRuntimeException(X, #Y);}

class SGXEnclaveRuntimeException : public EnclaveException
{
public:
	SGXEnclaveRuntimeException() = delete;
	SGXEnclaveRuntimeException(sgx_status_t errCode, const std::string& funcName);
	virtual ~SGXEnclaveRuntimeException();

	virtual const char* what() const throw();

	sgx_status_t GetErrorCode() const;
	std::string GetFuncName() const;

private:
	sgx_status_t m_errCode;
	std::string m_funcName;
};
