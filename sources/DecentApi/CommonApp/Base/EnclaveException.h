#pragma once

#include "../../Common/RuntimeException.h"

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
