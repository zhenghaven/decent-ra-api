#pragma once

#include "../RuntimeException.h"

#include "ErrorCode.h"

#define DECENT_CHECK_SGX_STATUS_ERROR(X, Y) {\
                                                const auto val = X; \
                                                if(val != SGX_SUCCESS) {\
                                                    throw Decent::Sgx::RuntimeError(val, #Y);\
                                                }\
                                            }

#define DECENT_CHECK_SGX_FUNC_CALL_ERROR(FUNC, ...) \
            DECENT_CHECK_SGX_STATUS_ERROR(FUNC(__VA_ARGS__), FUNC)

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
