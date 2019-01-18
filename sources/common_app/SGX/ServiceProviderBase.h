#pragma once

#include "../Enclave/ServiceProvider.h"

namespace Decent
{
	namespace Sgx
	{
		class ServiceProviderBase : virtual public Base::ServiceProvider
		{
		public:
			using Base::ServiceProvider::ServiceProvider;
			virtual ~ServiceProviderBase() {}

			virtual const char* GetPlatformType() const override { return "SGX"; }
		};
	}
}
