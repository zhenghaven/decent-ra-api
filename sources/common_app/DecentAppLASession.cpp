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

bool DecentServerLASession::SmartMsgEntryPoint(std::unique_ptr<Connection>& connection, EnclaveBase & hwEnclave, DecentEnclave & enclave, const Json::Value & jsonMsg)
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
	try
	{
		res = serverSession->PerformDecentServerSideLA();
		serverSession->SwapConnection(connection);
	}
	catch (...)
	{//Make sure the connectino is not closed by app session.
		if (!connection)
		{
			serverSession->SwapConnection(connection);
		}
		throw;
	}
	return res;
}

DecentServerLASession::DecentServerLASession(std::unique_ptr<Connection>& connection, EnclaveBase & hwEnclave, DecentEnclave & enclave, const Json::Value & jsonMsg) :
	DecentServerLASession(connection, hwEnclave, enclave, hwEnclave.GetLAResponderSession(connection, jsonMsg))
{
}

DecentServerLASession::DecentServerLASession(std::unique_ptr<Connection>& connection, EnclaveBase& hwEnclave, DecentEnclave& enclave, const std::shared_ptr<LocalAttestationSession>& laSession) :
	k_senderId(laSession->GetSenderID()),
	k_remoteSideId(laSession->GetRemoteReceiverID()),
	m_decentEnclave(enclave),
	m_laSession(laSession)
{
	m_laSession->SwapConnection(m_connection);
}

bool DecentServerLASession::PerformDecentServerSideLA()
{
	if (!m_connection || !m_laSession)
	{
		return false;
	}

	m_laSession->SwapConnection(m_connection);
	bool res = m_laSession->PerformResponderSideLA();
	m_laSession->SwapConnection(m_connection);
	if (!res)
	{
		return false;
	}

	Json::Value jsonRoot;
	m_connection->Receive(jsonRoot);

	try
	{
		std::unique_ptr<DecentAppTrustedMessage> reqMsg(ParseMessageExpected<DecentAppTrustedMessage>(jsonRoot));
		res = m_decentEnclave.ProcessAppReportSignReq(k_remoteSideId, m_connection, reqMsg->GetTrustedMsg(), m_decentEnclave.GetDecentSelfRAReport().c_str());
		if (!res)
		{
			m_connection->Send(DecentAppErrMsg(k_senderId, "Enclave process error!"));
			return false;
		}
	}
	catch (const MessageParseException&)
	{
		m_connection->Send(DecentAppErrMsg(k_senderId, "Received unexpected message! Make sure you are following the protocol."));
		return false;
	}

	//Job done, we need to close the connection, so return false;
	return false;
}

bool DecentAppLASession::SendHandshakeMessage(std::unique_ptr<Connection>& connection, EnclaveBase & hwEnclave)
{
	return hwEnclave.SendLARequest(connection);
}

bool DecentAppLASession::SmartMsgEntryPoint(std::unique_ptr<Connection>& connection, EnclaveBase & hwEnclave, DecentAppEnclave & enclave, const Json::Value & jsonMsg)
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
	try
	{
		res = appSession->PerformDecentAppSideLA();
		appSession->SwapConnection(connection);
	}
	catch (...)
	{//Make sure the connectino is not closed by app session.
		if (!connection)
		{
			appSession->SwapConnection(connection);
		}
		throw;
	}
	return res;
}

DecentAppLASession::DecentAppLASession(std::unique_ptr<Connection>& connection, EnclaveBase & hwEnclave, DecentAppEnclave & enclave, const Json::Value & jsonMsg) :
	DecentAppLASession(connection, hwEnclave, enclave, hwEnclave.GetLAInitiatorSession(connection, jsonMsg))
{
}

DecentAppLASession::DecentAppLASession(std::unique_ptr<Connection>& connection, EnclaveBase& hwEnclave, DecentAppEnclave& enclave, const std::shared_ptr<LocalAttestationSession>& laSession) :
	k_senderId(laSession->GetSenderID()),
	k_remoteSideId(laSession->GetRemoteReceiverID()),
	m_appEnclave(enclave),
	m_laSession(laSession)
{
	m_laSession->SwapConnection(m_connection);
}

bool DecentAppLASession::PerformDecentAppSideLA()
{
	if (!m_connection || !m_laSession)
	{
		return false;
	}

	m_laSession->SwapConnection(m_connection);
	bool res = m_laSession->PerformInitiatorSideLA();
	m_laSession->SwapConnection(m_connection);
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
	m_connection->Receive(jsonRoot);

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
