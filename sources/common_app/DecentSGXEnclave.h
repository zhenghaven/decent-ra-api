#pragma once

#include "SGXEnclave.h"
#include "../common/Decent.h"

class DecentSGXEnclave : public SGXEnclave
{
public:
	using SGXEnclave::SGXEnclave;

	~DecentSGXEnclave();

	virtual std::unique_ptr<Connection> RequestRootNodeRA(uint32_t ipAddr, uint16_t portNum);

	virtual std::unique_ptr<Connection> AcceptRootNodeRAConnection();

	virtual void SetDecentMode(DecentNodeMode inDecentMode) = 0;

	virtual DecentNodeMode GetDecentMode() = 0;

protected:

private:

};
