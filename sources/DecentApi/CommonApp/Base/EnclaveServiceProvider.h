#pragma once

#include "EnclaveBase.h"
#include "ServiceProvider.h"

namespace Decent
{
	namespace Base
	{
		class EnclaveServiceProvider : virtual public EnclaveBase, virtual public ServiceProvider
		{
		};
	}
}

