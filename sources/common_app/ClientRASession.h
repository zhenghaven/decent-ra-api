#pragma once

#include <memory>
#include <string>
#include "CommSession.h"

class ClientRASession : public CommSession
{

public:
	virtual ~ClientRASession() {}

	virtual bool ProcessClientSideRA() = 0;
};
