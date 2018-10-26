#pragma once

#include <string>

#include "Networking/ConnectionHandler.h"

typedef struct _general_secp256r1_public_t general_secp256r1_public_t;

class ServiceProviderBase : virtual public ConnectionHandler
{
public:
	virtual ~ServiceProviderBase() {}

	virtual const char* GetPlatformType() const = 0;

	virtual void GetSpPublicSignKey(general_secp256r1_public_t& outKey) const = 0;

	virtual const std::string GetSpPublicSignKey() const;
};
