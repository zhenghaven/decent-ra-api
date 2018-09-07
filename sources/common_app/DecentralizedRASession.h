#pragma once

#include <string>

#include "CommSession.h"

class DecentralizedEnclave;
class Connection;
class EnclaveServiceProviderBase;
class DecentralizedRAHandshake;
class DecentralizedRAHandshakeAck;
namespace Json
{
	class Value;
}

class DecentralizedRASession : public CommSession
{
public:
	static void SendHandshakeMessage(Connection& connection, EnclaveServiceProviderBase& enclave);
	static bool SmartMsgEntryPoint(Connection& connection, EnclaveServiceProviderBase& hwEnclave, DecentralizedEnclave& enclave, const Json::Value& jsonMsg);

public:
	DecentralizedRASession() = delete;
	DecentralizedRASession(Connection& connection, EnclaveServiceProviderBase& hwEnclave, DecentralizedEnclave& enclave);
	DecentralizedRASession(Connection& connection, EnclaveServiceProviderBase& hwEnclave, DecentralizedEnclave& enclave, const DecentralizedRAHandshake& hsMsg);
	DecentralizedRASession(Connection& connection, EnclaveServiceProviderBase& hwEnclave, DecentralizedEnclave& enclave, const DecentralizedRAHandshakeAck& ackMsg);
	
	virtual ~DecentralizedRASession();

	virtual bool ProcessClientSideRA();

	virtual bool ProcessServerSideRA();

	virtual const std::string GetSenderID() const override { return k_senderId; }

	virtual const std::string GetRemoteReceiverID() const override { return k_remoteSideId; }

protected:
	virtual bool SendReverseRARequest(const std::string& senderID);

	virtual bool RecvReverseRARequest();

	EnclaveServiceProviderBase& m_hwEnclave;

private:
	const std::string k_senderId;
	const std::string k_remoteSideId;
	DecentralizedEnclave& m_decentralizedEnc;
	const bool k_isServerSide;
};
