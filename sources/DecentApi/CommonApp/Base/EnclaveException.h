#pragma once

#include "../../Common/Exceptions.h"

#define DECENT_ASSERT_ENCLAVE_APP_RESULT(X, INFO) if(!(X)) { throw Decent::Base::EnclaveAppException("Failed to " INFO); }

namespace Decent
{
	namespace Base
	{
		class EnclaveAppException : public Decent::RuntimeException
		{
		public:
			using RuntimeException::RuntimeException;
		};
	}
}
