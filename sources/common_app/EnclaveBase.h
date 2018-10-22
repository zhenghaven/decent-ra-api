#pragma once

#include <string>

#include "Networking/ConnectionHandler.h"

class EnclaveBase : virtual public ConnectionHandler
{
public:
	virtual ~EnclaveBase() {}

	virtual const char* GetPlatformType() const = 0;
};

