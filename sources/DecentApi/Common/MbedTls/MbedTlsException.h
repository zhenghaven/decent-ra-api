#pragma once

#include "RuntimeException.h"

namespace Decent
{
	namespace MbedTlsObj
	{
		class MbedTlsException : public RuntimeException
		{
		public:
			explicit MbedTlsException(const char* funcName, const int errorcode) :
				RuntimeException("Mbed TLS error in function " + std::string(funcName) + ". ErrorCode: " + ErrorCodeToStr(errorcode) + ". ")
			{}

		private:
			static std::string ErrorCodeToStr(int error);
		};
	}
}
