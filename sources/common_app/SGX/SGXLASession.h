#pragma once

#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL

#include "../LocalAttestationSession.h"

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

private:
	SGXEnclave & m_sgxEnclave;
	const std::string k_remoteSideID;
	std::unique_ptr<const SGXLAMessage1> m_initorMsg1;
};

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL
