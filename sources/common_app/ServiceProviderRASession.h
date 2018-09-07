#pragma once

#include "CommSession.h"

class ServiceProviderRASession : public CommSession
{
public:
	using CommSession::CommSession;

	virtual ~ServiceProviderRASession() {}

	virtual bool ProcessServerSideRA() = 0;
};
