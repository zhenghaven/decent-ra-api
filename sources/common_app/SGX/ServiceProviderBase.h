#pragma once

#include "../ServiceProviderBase.h"

namespace Sgx
{
	class ServiceProviderBase : virtual public ::ServiceProviderBase
	{
	public:
		using ::ServiceProviderBase::ServiceProviderBase;
		virtual ~ServiceProviderBase() {}

		virtual const char* GetPlatformType() const override { return "SGX"; }
	};
}


