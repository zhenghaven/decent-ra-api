#pragma once

#include <string>

//#include "EnclaveServiceProviderBase.h"

class DecentralizedEnclave// : virtual public EnclaveServiceProviderBase
{
public:
	virtual ~DecentralizedEnclave() {}

	virtual bool ToDecentralizedNode(const std::string& id, bool isSP) = 0;
};
