#pragma once

#include "RemoteAttestationSession.h"

class SGXRemoteAttestationSession : public RemoteAttestationSession
{
public:
	using RemoteAttestationSession::RemoteAttestationSession;

	~SGXRemoteAttestationSession();

	virtual RAMessages* SendMessages(const std::string& senderID, const RAMessages& msg) override;

	virtual void SendErrorMessages(const RAMessages& msg) override;

	virtual bool RecvMessages(const std::string& senderID, MsgProcessor msgProcessor) override;

protected:
	//virtual bool ProcessServerMessages();
	//virtual bool ProcessClientMessages();

private:

};
