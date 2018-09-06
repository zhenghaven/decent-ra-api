#pragma once

#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL

#include "../EnclaveException.h"

#include <string>

#include <sgx_error.h>

#define CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(X, Y) if(X != SGX_SUCCESS) {\
                                                  throw SGXEnclaveRuntimeException(X, #Y);}

class SGXEnclaveRuntimeException : public EnclaveException
{
public:
	SGXEnclaveRuntimeException() = delete;
	SGXEnclaveRuntimeException(sgx_status_t errCode, const std::string& funcName) :
		m_errCode(errCode),
		m_funcName(funcName)
	{}

	virtual ~SGXEnclaveRuntimeException() {}

	virtual const char* what() const throw()
	{
		return "SGX Enclave Runtime Exception";
	}

	sgx_status_t GetErrorCode() const { return m_errCode; }
	std::string GetFuncName() const { return m_funcName; }

private:
	sgx_status_t m_errCode;
	std::string m_funcName;
};

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL
