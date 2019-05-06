#pragma once

#include <string>

#include "../../Common/Net/ConnectionHandler.h"

typedef struct _general_secp256r1_public_t general_secp256r1_public_t;

namespace Decent
{
	namespace Base
	{
		class ServiceProvider : virtual public Net::ConnectionHandler
		{
		public:
			virtual ~ServiceProvider() {}

			virtual const char* GetPlatformType() const = 0;

			virtual void GetSpPublicSignKey(general_secp256r1_public_t& outKey) const = 0;

			virtual const std::string GetSpPublicSignKey() const;
		};
	}
}

