#pragma once

#include <memory>
#include <string>
#include "CommSession.h"

class Connection;

class LocalAttestationSession : public CommSession
{
public:
	using CommSession::CommSession;

	virtual ~LocalAttestationSession() {}

	virtual bool PerformInitiatorSideLA() = 0;
	virtual bool PerformResponderSideLA() = 0;
};
