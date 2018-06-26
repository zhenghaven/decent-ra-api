#pragma once

#include "DecentralizedRASession.h"

#include <string>

class DecentEnclave;

class DecentRASession : public DecentralizedRASession
{
public:
	//DecentSGXRASession() = delete;

	using DecentralizedRASession::DecentralizedRASession;

	~DecentRASession();

	virtual bool SendReverseRARequest(const std::string& senderID);

	virtual bool RecvReverseRARequest();

	//virtual bool ProcessClientSideRA(DecentEnclave& enclave) override;

	//virtual bool ProcessServerSideRA(DecentEnclave& enclave) override;

	virtual bool ProcessClientSideKeyRequest(DecentEnclave& enclave);

	/**
	 * Process the server side key request. This method should only used by root server.
	 *
	 * \param [in,out] enclave The enclave object.
	 *
	 * \return True if it succeeds, false if it fails.
	 */
	virtual bool ProcessServerSideKeyRequest(DecentEnclave& enclave);

	virtual bool ProcessClientMessage0(DecentEnclave& enclave);

	virtual bool ProcessServerMessage0(DecentEnclave& enclave);

protected:

private:

};
