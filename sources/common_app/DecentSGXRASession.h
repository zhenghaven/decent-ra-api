#pragma once

#include "RemoteAttestationSession.h"

class DecentSGXRASession : public RemoteAttestationSession
{
public:
	DecentSGXRASession() = delete;

	using RemoteAttestationSession::RemoteAttestationSession;

	~DecentSGXRASession();

	virtual bool SendReverseRARequest(const std::string& senderID);

	virtual bool RecvReverseRARequest();

	virtual bool ProcessClientSideRA(EnclaveBase& enclave) override;

	virtual bool ProcessServerSideRA(EnclaveBase& enclave) override;

protected:

private:

};
