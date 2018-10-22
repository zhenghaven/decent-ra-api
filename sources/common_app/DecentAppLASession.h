#pragma once

#include <memory>
#include <string>
#include "CommSession.h"

namespace Json
{
	class Value;
}
class DecentEnclave;
class DecentAppEnclave;
class EnclaveBase;
class EnclaveServiceProviderBase;
class LocalAttestationSession;
class DecentLogger;
class DecentAppHandshake;
class DecentAppHandshakeAck;

class DecentServerLASession : public CommSession
{
public:
	static bool SmartMsgEntryPoint(Connection& connection, EnclaveServiceProviderBase& hwEnclave, DecentEnclave& enclave, const Json::Value& jsonMsg);

public:
	DecentServerLASession() = delete;
	DecentServerLASession(Connection& connection, EnclaveServiceProviderBase& hwEnclave, DecentEnclave& enclave, const DecentAppHandshake& hsMsh);
	//DecentServerLASession(Connection& connection, EnclaveBase& hwEnclave, DecentEnclave& enclave, const Json::Value& jsonMsg);

	virtual ~DecentServerLASession();

	virtual bool PerformDecentServerSideLA(DecentLogger* logger = nullptr);

	virtual const std::string GetSenderID() const override { return k_senderId; }

	virtual const std::string GetRemoteReceiverID() const override { return ""; }

private:
	const std::string k_senderId;
	DecentEnclave& m_decentEnclave;
};

class DecentAppLASession : public CommSession
{
public:
	static void SendHandshakeMessage(Connection& connection, EnclaveBase& hwEnclave);
	static bool SmartMsgEntryPoint(Connection& connection, EnclaveBase& hwEnclave, DecentAppEnclave& enclave, const Json::Value& jsonMsg);

public:
	DecentAppLASession() = delete;
	DecentAppLASession(Connection& connection, EnclaveBase& hwEnclave, DecentAppEnclave& enclave, const DecentAppHandshakeAck& hsAck);
	//DecentAppLASession(Connection& connection, EnclaveBase& hwEnclave, DecentAppEnclave& enclave, const Json::Value& jsonMsg);

	virtual ~DecentAppLASession();

	virtual bool PerformDecentAppSideLA();

	virtual const std::string GetSenderID() const override { return ""; }

	virtual const std::string GetRemoteReceiverID() const override { return k_remoteSideId; }

private:
	const std::string k_remoteSideId;
	DecentAppEnclave& m_appEnclave;

	const std::string k_selfReport;
};
