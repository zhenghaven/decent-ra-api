#include "DecentAppLASession.h"

#include <json/json.h>

#include "EnclaveBase.h"
#include "DecentEnclave.h"
#include "DecentAppEnclave.h"
#include "LocalAttestationSession.h"
#include "DecentMessages/DecentAppMessage.h"
#include "MessageException.h"
#include "Networking/Connection.h"

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

bool DecentServerLASession::SmartMsgEntryPoint(Connection& connection, EnclaveBase & hwEnclave, DecentEnclave & enclave, const Json::Value & jsonMsg)
{
	std::unique_ptr<DecentServerLASession> serverSession;
	try
	{
		serverSession.reset(new DecentServerLASession(connection, hwEnclave, enclave, jsonMsg));
	}
	catch (const MessageParseException&)
	{
		return false;
	}

	bool res = false;
	res = serverSession->PerformDecentServerSideLA();
	return res;
}

DecentServerLASession::DecentServerLASession(Connection& connection, EnclaveBase & hwEnclave, DecentEnclave & enclave, const Json::Value & jsonMsg) :
	DecentServerLASession(connection, hwEnclave, enclave, hwEnclave.GetLAResponderSession(connection, jsonMsg))
{
}

DecentServerLASession::~DecentServerLASession()
{
}

DecentServerLASession::DecentServerLASession(Connection& connection, EnclaveBase& hwEnclave, DecentEnclave& enclave, LocalAttestationSession* laSession) :
	CommSession(connection),
	k_senderId(laSession->GetSenderID()),
	k_remoteSideId(laSession->GetRemoteReceiverID()),
	m_decentEnclave(enclave),
	m_laSession(std::move(laSession))
{
}

bool DecentServerLASession::PerformDecentServerSideLA()
{
	if (!m_laSession)
	{
		return false;
	}

	bool res = m_laSession->PerformResponderSideLA();
	if (!res)
	{
		return false;
	}

	Json::Value jsonRoot;
	m_connection.Receive(jsonRoot);

	try
	{
		std::unique_ptr<DecentAppTrustedMessage> reqMsg(ParseMessageExpected<DecentAppTrustedMessage>(jsonRoot));
		res = m_decentEnclave.ProcessAppReportSignReq(k_remoteSideId, m_connection, reqMsg->GetTrustedMsg(), m_decentEnclave.GetDecentSelfRAReport().c_str());
		if (!res)
		{
			m_connection.Send(DecentAppErrMsg(k_senderId, "Enclave process error!"));
			return false;
		}
	}
	catch (const MessageParseException&)
	{
		m_connection.Send(DecentAppErrMsg(k_senderId, "Received unexpected message! Make sure you are following the protocol."));
		return false;
	}

	//Job done, we need to close the connection, so return false;
	return false;
}

bool DecentAppLASession::SendHandshakeMessage(Connection& connection, EnclaveBase & hwEnclave)
{
	return hwEnclave.SendLARequest(connection);
}

bool DecentAppLASession::SmartMsgEntryPoint(Connection& connection, EnclaveBase & hwEnclave, DecentAppEnclave & enclave, const Json::Value & jsonMsg)
{
	std::unique_ptr<DecentAppLASession> appSession;
	try
	{
		appSession.reset(new DecentAppLASession(connection, hwEnclave, enclave, jsonMsg));
	}
	catch (const MessageParseException&)
	{
		return false;
	}

	bool res = false;
	res = appSession->PerformDecentAppSideLA();
	return res;
}

DecentAppLASession::DecentAppLASession(Connection& connection, EnclaveBase & hwEnclave, DecentAppEnclave & enclave, const Json::Value & jsonMsg) :
	DecentAppLASession(connection, hwEnclave, enclave, hwEnclave.GetLAInitiatorSession(connection, jsonMsg))
{
}

DecentAppLASession::~DecentAppLASession()
{
}

DecentAppLASession::DecentAppLASession(Connection& connection, EnclaveBase& hwEnclave, DecentAppEnclave& enclave, LocalAttestationSession* laSession) :
	CommSession(connection),
	k_senderId(laSession->GetSenderID()),
	k_remoteSideId(laSession->GetRemoteReceiverID()),
	m_appEnclave(enclave),
	m_laSession(std::move(laSession))
{
}

bool DecentAppLASession::PerformDecentAppSideLA()
{
	if (!m_laSession)
	{
		return false;
	}

	bool res = m_laSession->PerformInitiatorSideLA();
	if (!res)
	{
		return false;
	}

	res = m_appEnclave.SendReportDataToServer(k_remoteSideId, m_connection);
	if (!res)
	{
		return false;
	}

	Json::Value jsonRoot;
	m_connection.Receive(jsonRoot);

	try
	{
		std::unique_ptr<DecentAppTrustedMessage> trustedMsg(ParseMessageExpected<DecentAppTrustedMessage>(jsonRoot));
		std::string decentSelfRAReport = trustedMsg->GetAppAttach();
		res = m_appEnclave.ProcessDecentSelfRAReport(decentSelfRAReport);
		if (!res)
		{
			return false;
		}

		res = m_appEnclave.ProcessAppReportSignMsg(trustedMsg->GetTrustedMsg());
		if (!res)
		{
			return false;
		}
	}
	catch (const MessageParseException&)
	{//Don't need to send error message. The remote side may already close the connection.
		return false;
	}

	//Job done, we need to close the connection, so return false;
	return false;
}
