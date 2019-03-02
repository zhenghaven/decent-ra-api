#pragma once

#include "../Base/EnclaveException.h"

#include <string>

#include <sgx_error.h>

#include "EnclaveUtil.h"

#define CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(X, Y) if(X != SGX_SUCCESS) {\
                                                  throw Decent::Sgx::EnclaveRuntimeException(X, #Y);}

#define CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION_INT(X, Y) if(!X) {\
                                                  throw Decent::Sgx::EnclaveRuntimeException(SGX_ERROR_UNEXPECTED, #Y);}

namespace Decent
{
	namespace Sgx
	{
		class EnclaveRuntimeException : public Base::EnclaveAppException
		{
		private:
			static std::string GetSgxErrorMsg(const sgx_status_t errCode) noexcept
			{
				try
				{
					return GetErrorMessage(errCode);
				}
				catch (...)
				{
					return "Unknown Error";
				}
			}

		public:
			EnclaveRuntimeException() = delete;
			EnclaveRuntimeException(sgx_status_t errCode, const std::string& funcName) :
				Base::EnclaveAppException("SGX Runtime Error:\nFunction: " + 
				funcName + "\nSGX Err Msg: " + GetSgxErrorMsg(errCode))
			{}

		};
	}
}
