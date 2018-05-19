#pragma once

#include "RemoteAttestationSession.h"

class SGXRemoteAttestationSession : public RemoteAttestationSession
{
public:
	using RemoteAttestationSession::RemoteAttestationSession;

	~SGXRemoteAttestationSession();

	virtual bool ProcessMessages() override;

private:

};
