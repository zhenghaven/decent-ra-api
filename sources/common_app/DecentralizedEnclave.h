#pragma once

#include <string>

#include <sgx_error.h>

class DecentralizedEnclave
{
public:
	virtual ~DecentralizedEnclave();

	virtual sgx_status_t TransitToDecentNode(const std::string& id, bool isSP) = 0;
};
