#pragma once

#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL

#include "../LocalAttestationSession.h"

#include "SGXEnclave.h"

#include <memory>

class SGXEnclave;
class SGXLARequest;
class SGXLAMessage1;
namespace Json
{
	class Value;
}

class SGXLASession : public LocalAttestationSession
{
public:
	static bool SendHandshakeMessage(std::unique_ptr<Connection>& connection, SGXEnclave& enclave);
	static bool SmartMsgEntryPoint(std::unique_ptr<Connection>& connection, SGXEnclave& enclave, const Json::Value& msg);

public:
	SGXLASession() = delete;
	//Caution: blocking constructor:
	SGXLASession(std::unique_ptr<Connection>& connection, SGXEnclave& enclave);
	SGXLASession(std::unique_ptr<Connection>& connection, SGXEnclave& enclave, const SGXLARequest& msg);
	SGXLASession(std::unique_ptr<Connection>& connection, SGXEnclave& enclave, const SGXLAMessage1* msg);

	virtual ~SGXLASession();

	virtual bool PerformInitiatorSideLA() override;

	virtual bool PerformResponderSideLA() override;

	virtual const std::string GetSenderID() const override { return k_senderId; }

	virtual const std::string GetRemoteReceiverID() const override { return k_remoteSideId; }

private:
	const std::string k_senderId;
	const std::string k_remoteSideId;
	SGXEnclave& m_hwEnclave;
	std::unique_ptr<const SGXLAMessage1> m_initorMsg1;
};

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL
