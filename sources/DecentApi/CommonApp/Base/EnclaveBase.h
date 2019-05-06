#pragma once

#include <string>

#include "../../Common/Net/ConnectionHandler.h"

namespace Decent
{
	namespace Base
	{
		class EnclaveBase : virtual public Net::ConnectionHandler
		{
		public:
			virtual ~EnclaveBase() {}

			virtual const char* GetPlatformType() const = 0;
		};
	}
}
