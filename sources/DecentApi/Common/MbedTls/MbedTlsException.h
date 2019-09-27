#pragma once

#include "RuntimeException.h"
#include "MbedTlsCppDefs.h"

namespace Decent
{
	namespace MbedTlsObj
	{
		class MbedTlsException : public RuntimeException
		{
		public:
			explicit MbedTlsException(const char* funcName, const int errorcode) :
				RuntimeException("Mbed TLS error in function " + std::string(funcName) + ". ErrorCode: " + ErrorCodeToHexStr(errorcode) + ". "),
				m_errorCode(errorcode)
			{}

			int GetErrorCode() const noexcept
			{
				return m_errorCode;
			}

		private:
			static std::string ErrorCodeToHexStr(int error);

			const int m_errorCode;
		};
	}
}

#define CALL_MBEDTLS_C_FUNC(FUNC, ...) {int retVal = FUNC(__VA_ARGS__); if(retVal != Decent::MbedTlsObj::MBEDTLS_SUCCESS_RET) { throw Decent::MbedTlsObj::MbedTlsException(#FUNC, retVal); } }
