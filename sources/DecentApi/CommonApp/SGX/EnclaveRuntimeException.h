#pragma once

#include "../Base/EnclaveException.h"

#include <string>

#include <sgx_error.h>

#define CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(X, Y) if(X != SGX_SUCCESS) {\
                                                  throw Decent::Sgx::EnclaveRuntimeException(X, #Y);}

#define CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION_INT(X, Y) if(!X) {\
                                                  throw Decent::Sgx::EnclaveRuntimeException(SGX_ERROR_UNEXPECTED, #Y);}

namespace Decent
{
	namespace Sgx
	{
		class EnclaveRuntimeException : public Base::EnclaveException
		{
		public:
			EnclaveRuntimeException() = delete;
			EnclaveRuntimeException(sgx_status_t errCode, const std::string& funcName) :
				m_errCode(errCode),
				m_funcName(funcName)
			{}

			virtual ~EnclaveRuntimeException() {}

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
	}
}
