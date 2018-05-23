#pragma once

#include "RemoteAttestationSession.h"

class SGXRemoteAttestationSession : public RemoteAttestationSession
{
public:
	using RemoteAttestationSession::RemoteAttestationSession;

	~SGXRemoteAttestationSession();

	virtual bool ProcessMessages() override;

protected:
	virtual bool ProcessServerMessages();
	virtual bool ProcessClientMessages();

private:

};
