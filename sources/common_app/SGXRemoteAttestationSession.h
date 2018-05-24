#pragma once

#include "RemoteAttestationSession.h"

class SGXRemoteAttestationSession : public RemoteAttestationSession
{
public:
	using RemoteAttestationSession::RemoteAttestationSession;

	~SGXRemoteAttestationSession();

	virtual RAMessages* SendMessages(const RAMessages& msg) override;

	virtual bool RecvMessages(MsgProcessor msgProcessor) override;

protected:
	//virtual bool ProcessServerMessages();
	//virtual bool ProcessClientMessages();

private:

};
