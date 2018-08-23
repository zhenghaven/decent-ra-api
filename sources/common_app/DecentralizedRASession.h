#pragma once

#include <memory>
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
	static void SendHandshakeMessage(std::unique_ptr<Connection>& connection, EnclaveServiceProviderBase& enclave);
	static bool SmartMsgEntryPoint(std::unique_ptr<Connection>& connection, EnclaveServiceProviderBase& hwEnclave, DecentralizedEnclave& enclave, const Json::Value& jsonMsg);

public:
	DecentralizedRASession() = delete;
	DecentralizedRASession(std::unique_ptr<Connection>& connection, EnclaveServiceProviderBase& hwEnclave, DecentralizedEnclave& enclave);
	DecentralizedRASession(std::unique_ptr<Connection>& connection, EnclaveServiceProviderBase& hwEnclave, DecentralizedEnclave& enclave, const DecentralizedRAHandshake& hsMsg);
	DecentralizedRASession(std::unique_ptr<Connection>& connection, EnclaveServiceProviderBase& hwEnclave, DecentralizedEnclave& enclave, const DecentralizedRAHandshakeAck& ackMsg);
	
	virtual ~DecentralizedRASession();

	virtual bool ProcessClientSideRA();

	virtual bool ProcessServerSideRA();

protected:
	virtual bool SendReverseRARequest(const std::string& senderID);

	virtual bool RecvReverseRARequest();

	EnclaveServiceProviderBase& m_hwEnclave;

private:
	const std::string k_senderID;
	const std::string k_remoteSideID;
	DecentralizedEnclave& m_decentralizedEnc;
	const bool k_isServerSide;
};
