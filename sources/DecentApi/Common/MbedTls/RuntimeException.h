#pragma once

#include "../RuntimeException.h"

namespace Decent
{
	namespace MbedTlsObj
	{
		class RuntimeException : public Decent::RuntimeException
		{
		public:
			using Decent::RuntimeException::RuntimeException;

		};
	}
}
