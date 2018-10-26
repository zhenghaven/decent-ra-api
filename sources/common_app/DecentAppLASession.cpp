#include "DecentAppLASession.h"

#include <json/json.h>

#include "EnclaveBase.h"
#include "EnclaveServiceProviderBase.h"
#include "DecentEnclave.h"
#include "DecentAppEnclave.h"
#include "DecentMessages/DecentAppMessage.h"
#include "MessageException.h"
#include "Networking/Connection.h"
#include "Logger/LoggerManager.h"

template<class T>
static inline T*  ParseMessageExpected(const Json::Value& json)
{
	static_assert(std::is_base_of<DecentAppMessage, T>::value, "Class type must be a child class of SGXLAMessage.");

	DecentAppMessage::ParseCat(json); //Make sure it's a smart message. Otherwise a ParseException will be thrown.

	if (DecentAppMessage::ParseType(json[Messages::sk_LabelRoot]) == DecentAppErrMsg::sk_ValueType)
	{
		throw ReceivedErrorMessageException();
	}

	return new T(json);
}

bool DecentServerLASession::SmartMsgEntryPoint(Connection& connection, EnclaveServiceProviderBase & hwEnclave, DecentEnclave & enclave, const Json::Value & jsonMsg)
{
	std::unique_ptr<DecentLogger> logger;

	const std::string inType = DecentAppMessage::ParseType(jsonMsg[Messages::sk_LabelRoot]);
	if (inType == DecentAppHandshake::sk_ValueType)
	{
		DecentAppHandshake hsMsg(jsonMsg);
		logger = std::make_unique<DecentLogger>(hsMsg.GetSenderID());
		logger->AddMessage('I', "Received DecentApp LA Request.");
		DecentServerLASession laSession(connection, hwEnclave, enclave, hsMsg);
		bool res = laSession.PerformDecentServerSideLA(logger.get());
		logger->AddMessage('I', "Completed Processing DecentApp LA Request.");
		DecentLoggerManager::GetInstance().AddLogger(logger);
		return res;
	}
	return false;
}

DecentServerLASession::~DecentServerLASession()
{
}

DecentServerLASession::DecentServerLASession(Connection& connection, EnclaveServiceProviderBase& hwEnclave, DecentEnclave& enclave, const DecentAppHandshake& hsMsh) :
	CommSession(connection),
	k_senderId(hwEnclave.GetSpPublicSignKey()),
	m_decentEnclave(enclave)
{
	connection.SendPack(DecentAppHandshakeAck(k_senderId, enclave.GetDecentSelfRAReport()));
}

bool DecentServerLASession::PerformDecentServerSideLA(DecentLogger* logger)
{
	bool res = m_decentEnclave.ProcessAppX509Req(m_connection);

	logger->AddMessage('I', res ? "New App Attested Successfully!" : "New App Failed Attestion!");

	//Job done, we need to close the connection, so return false;
	return false;
}

void DecentAppLASession::SendHandshakeMessage(Connection& connection, EnclaveBase & hwEnclave)
{
	connection.SendPack(DecentAppHandshake(std::string("AppLaReq")));
}

bool DecentAppLASession::SmartMsgEntryPoint(Connection& connection, EnclaveBase & hwEnclave, DecentAppEnclave & enclave, const Json::Value & jsonMsg)
{
	const std::string inType = DecentAppMessage::ParseType(jsonMsg[Messages::sk_LabelRoot]);
	if (inType == DecentAppHandshakeAck::sk_ValueType)
	{
		DecentAppHandshakeAck hsAckMsg(jsonMsg);
		DecentAppLASession laSession(connection, hwEnclave, enclave, hsAckMsg);
		bool res = laSession.PerformDecentAppSideLA();
		return res;
	}
	return false;
}

DecentAppLASession::~DecentAppLASession()
{
}

DecentAppLASession::DecentAppLASession(Connection& connection, EnclaveBase& hwEnclave, DecentAppEnclave& enclave, const DecentAppHandshakeAck& hsAck) :
	CommSession(connection),
	k_remoteSideId(hsAck.GetSenderID()),
	m_appEnclave(enclave),
	k_selfReport(hsAck.GetSelfRAReport())
{
}

bool DecentAppLASession::PerformDecentAppSideLA()
{
	if (!m_appEnclave.ProcessDecentSelfRAReport(k_selfReport))
	{
		return false;
	}

	m_appEnclave.GetX509FromServer(k_remoteSideId, m_connection);

	//Job done, we need to close the connection, so return false;
	return false;
}
