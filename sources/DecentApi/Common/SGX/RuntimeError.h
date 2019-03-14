#pragma once

#include "../RuntimeException.h"

#include "ErrorCode.h"

#define DECENT_CHECK_SGX_STATUS_ERROR(X, Y) if(X != SGX_SUCCESS) {\
                                                  throw Decent::Sgx::RuntimeError(X, #Y);}

namespace Decent
{
	namespace Sgx
	{
		class RuntimeError : public RuntimeException
		{
		public:
			RuntimeError() = delete;

			RuntimeError(sgx_status_t errCode, const std::string& funcName) :
				RuntimeException(ConstructErrorMsg(errCode, funcName))
			{}

		};
	}
}
