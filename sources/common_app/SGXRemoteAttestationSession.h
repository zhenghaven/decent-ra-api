#pragma once

#include "RemoteAttestationSession.h"

class SGXRemoteAttestationSession : public RemoteAttestationSession
{
public:
	using RemoteAttestationSession::RemoteAttestationSession;

	~SGXRemoteAttestationSession();

	virtual bool ProcessClientSideRA(EnclaveBase& enclave) override;

	virtual bool ProcessServerSideRA(EnclaveBase& enclave) override;

protected:

private:

};
