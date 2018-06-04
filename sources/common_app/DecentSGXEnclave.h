#pragma once

#include "SGXEnclave.h"

class DecentSGXEnclave : public SGXEnclave
{
public:
	using SGXEnclave::SGXEnclave;

	~DecentSGXEnclave();

	virtual std::unique_ptr<Connection> RequestRootNodeRA(uint32_t ipAddr, uint16_t portNum);

	virtual std::unique_ptr<Connection> AcceptRootNodeRAConnection();

protected:

private:

};
