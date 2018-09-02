#pragma once

#include <string>
#include <memory>
#include "CommSession.h"

namespace Json
{
	class Value;
}
class DecentEnclave;
class DecentAppEnclave;
class EnclaveBase;
class LocalAttestationSession;

class DecentServerLASession : public CommSession
{
public:
	static bool SmartMsgEntryPoint(std::unique_ptr<Connection>& connection, EnclaveBase& hwEnclave, DecentEnclave& enclave, const Json::Value& jsonMsg);

public:
	DecentServerLASession() = delete;
	DecentServerLASession(std::unique_ptr<Connection>& connection, EnclaveBase& hwEnclave, DecentEnclave& enclave, const Json::Value& jsonMsg);

	virtual ~DecentServerLASession() {}

	virtual bool PerformDecentServerSideLA();

	virtual const std::string GetSenderID() const override { return k_senderId; }

	virtual const std::string GetRemoteReceiverID() const override { return k_remoteSideId; }

private:
	DecentServerLASession(std::unique_ptr<Connection>& connection, EnclaveBase& hwEnclave, DecentEnclave& enclave, const std::shared_ptr<LocalAttestationSession>& laSession);

private:
	const std::string k_senderId;
	const std::string k_remoteSideId;
	DecentEnclave& m_decentEnclave;

	std::shared_ptr<LocalAttestationSession> m_laSession;
};

class DecentAppLASession : public CommSession
{
public:
	static bool SendHandshakeMessage(std::unique_ptr<Connection>& connection, EnclaveBase& hwEnclave);
	static bool SmartMsgEntryPoint(std::unique_ptr<Connection>& connection, EnclaveBase& hwEnclave, DecentAppEnclave& enclave, const Json::Value& jsonMsg);

public:
	DecentAppLASession() = delete;
	DecentAppLASession(std::unique_ptr<Connection>& connection, EnclaveBase& hwEnclave, DecentAppEnclave& enclave, const Json::Value& jsonMsg);

	virtual ~DecentAppLASession() {}

	virtual bool PerformDecentAppSideLA();

	virtual const std::string GetSenderID() const override { return k_senderId; }

	virtual const std::string GetRemoteReceiverID() const override { return k_remoteSideId; }

private:
	DecentAppLASession(std::unique_ptr<Connection>& connection, EnclaveBase& hwEnclave, DecentAppEnclave& enclave, const std::shared_ptr<LocalAttestationSession>& laSession);

private:
	const std::string k_senderId;
	const std::string k_remoteSideId;
	DecentAppEnclave& m_appEnclave;

	std::shared_ptr<LocalAttestationSession> m_laSession;
};
