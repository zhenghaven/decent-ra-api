#pragma once

#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL

#include "../ClientRASession.h"

#include <memory>

#include <sgx_tcrypto.h>

class SGXEnclave;
class SGXRAMessage0Resp;
namespace Json
{
	class Value;
}

class SGXClientRASession : public ClientRASession
{
public:
	static void SendHandshakeMessage(Connection& connection, SGXEnclave& enclave);
	static bool SmartMsgEntryPoint(Connection& connection, SGXEnclave& enclave, const Json::Value& msg);

public:
	SGXClientRASession() = delete;
	//Caution: blocking constructor:
	SGXClientRASession(Connection& connection, SGXEnclave& enclave);
	SGXClientRASession(Connection& connection, SGXEnclave& enclave, const SGXRAMessage0Resp& msg0r);

	virtual ~SGXClientRASession();

	virtual bool ProcessClientSideRA() override;

	virtual const std::string GetSenderID() const override { return k_senderId; }

	virtual const std::string GetRemoteReceiverID() const override { return k_remoteSideId; }

protected:
	const std::string k_senderId;
	const std::string k_remoteSideId;
	SGXEnclave& m_hwEnclave;
	const sgx_ec256_public_t k_remoteSideSignKey;
};

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL
