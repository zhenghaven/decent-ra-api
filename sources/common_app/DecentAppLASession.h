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
class LocalAttestationSession;
class DecentLogger;

class DecentServerLASession : public CommSession
{
public:
	static bool SmartMsgEntryPoint(Connection& connection, EnclaveBase& hwEnclave, DecentEnclave& enclave, const Json::Value& jsonMsg);

public:
	DecentServerLASession() = delete;
	DecentServerLASession(Connection& connection, EnclaveBase& hwEnclave, DecentEnclave& enclave, const Json::Value& jsonMsg);

	virtual ~DecentServerLASession();

	virtual bool PerformDecentServerSideLA(DecentLogger* logger = nullptr);

	virtual const std::string GetSenderID() const override { return k_senderId; }

	virtual const std::string GetRemoteReceiverID() const override { return k_remoteSideId; }

private:
	DecentServerLASession(Connection& connection, EnclaveBase& hwEnclave, DecentEnclave& enclave, LocalAttestationSession* laSession);

private:
	const std::string k_senderId;
	const std::string k_remoteSideId;
	DecentEnclave& m_decentEnclave;

	std::unique_ptr<LocalAttestationSession> m_laSession;
};

class DecentAppLASession : public CommSession
{
public:
	static bool SendHandshakeMessage(Connection& connection, EnclaveBase& hwEnclave);
	static bool SmartMsgEntryPoint(Connection& connection, EnclaveBase& hwEnclave, DecentAppEnclave& enclave, const Json::Value& jsonMsg);

public:
	DecentAppLASession() = delete;
	DecentAppLASession(Connection& connection, EnclaveBase& hwEnclave, DecentAppEnclave& enclave, const Json::Value& jsonMsg);

	virtual ~DecentAppLASession();

	virtual bool PerformDecentAppSideLA();

	virtual const std::string GetSenderID() const override { return k_senderId; }

	virtual const std::string GetRemoteReceiverID() const override { return k_remoteSideId; }

private:
	DecentAppLASession(Connection& connection, EnclaveBase& hwEnclave, DecentAppEnclave& enclave, LocalAttestationSession* laSession);

private:
	const std::string k_senderId;
	const std::string k_remoteSideId;
	DecentAppEnclave& m_appEnclave;

	std::unique_ptr<LocalAttestationSession> m_laSession;
};
