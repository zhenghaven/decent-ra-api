#pragma once

#include "CommSession.h"

class ServiceProviderRASession : public CommSession
{
public:
	virtual ~ServiceProviderRASession() {}

	virtual bool ProcessServerSideRA() = 0;
};
