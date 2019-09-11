#pragma once

#include <type_traits>

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

#define DECENT_SGX_CALL_WITH_INTBOOL_ERROR_1(FUNC) \
	{\
		int retVal = false; \
		const auto sgxRet = FUNC(&retVal); \
		if (sgxRet != SGX_SUCCESS) {\
			throw Decent::Sgx::RuntimeError(sgxRet, #FUNC); \
		} \
		if (!retVal) { \
			throw Decent::RuntimeException(#FUNC "return failed."); \
		} \
	}

#define DECENT_SGX_CALL_WITH_INTBOOL_ERROR(FUNC, ...) \
	{\
		int retVal = false; \
		const auto sgxRet = FUNC(&retVal, __VA_ARGS__); \
		if (sgxRet != SGX_SUCCESS) {\
			throw Decent::Sgx::RuntimeError(sgxRet, #FUNC); \
		} \
		if (!retVal) { \
			throw Decent::RuntimeException(#FUNC "return failed."); \
		} \
	}

#define DECENT_SGX_CALL_WITH_PTR_ERROR_1(FUNC, PTR) \
	{\
		static_assert(std::is_pointer<decltype(PTR)>::value, #PTR "must be a pointer."); \
		const auto sgxRet = FUNC(&PTR); \
		if (sgxRet != SGX_SUCCESS) { \
			throw Decent::Sgx::RuntimeError(sgxRet, #FUNC); \
		} \
		if (PTR == nullptr) { \
			throw Decent::RuntimeException(#FUNC "return failed."); \
		} \
	}

#define DECENT_SGX_CALL_WITH_PTR_ERROR(FUNC, PTR, ...) \
	{\
		static_assert(std::is_pointer<decltype(PTR)>::value, #PTR "must be a pointer."); \
		const auto sgxRet = FUNC(&PTR, __VA_ARGS__); \
		if (sgxRet != SGX_SUCCESS) { \
			throw Decent::Sgx::RuntimeError(sgxRet, #FUNC); \
		} \
		if (PTR == nullptr) { \
			throw Decent::RuntimeException(#FUNC "return failed."); \
		} \
	}

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
