#include "DecentralizedRASession.h"

#include <json/json.h>

#include <sgx_tcrypto.h>

#include "Common.h"

#include "ClientRASession.h"
#include "ServiceProviderRASession.h"

#include "DecentralizedEnclave.h"
#include "EnclaveServiceProviderBase.h"

#include "DecentralizedMessage.h"
#include "MessageException.h"

#include "../common/DataCoding.h"
#include "../common/JsonTools.h"
#include "Networking/Connection.h"

template<class T>
static T*  ParseMessageExpected(const Json::Value& json)
{
	static_assert(std::is_base_of<DecentralizedMessage, T>::value, "Class type must be a child class of DecentralizedMessage.");
	
	DecentralizedMessage::ParseCat(json); //Make sure it's a smart message. Otherwise a ParseException will be thrown.

	if (DecentralizedMessage::ParseType(json[Messages::LABEL_ROOT]) == DecentralizedErrMsg::VALUE_TYPE)
	{
		throw ReceivedErrorMessageException();
	}

	return new T(json);
}

template<class T>
static T* ParseMessageExpected(const std::string& jsonStr)
{
	static_assert(std::is_base_of<DecentralizedMessage, T>::value, "Class type must be a child class of DecentralizedMessage.");

	Json::Value jsonRoot;
	if (!ParseStr2Json(jsonRoot, jsonStr))
	{
		throw MessageParseException();
	}

	return ParseMessageExpected<T>(jsonRoot);
}

static inline std::string ConstructSenderID(EnclaveServiceProviderBase & enclave)
{
	sgx_ec256_public_t signPubKey;
	enclave.GetRAClientSignPubKey(signPubKey);
	return SerializePubKey(signPubKey);
}

void DecentralizedRASession::SendHandshakeMessage(std::unique_ptr<Connection>& connection, EnclaveServiceProviderBase & enclave)
{
	DecentralizedRAHandshake msg0s(ConstructSenderID(enclave));
	connection->Send(msg0s.ToJsonString());
}

bool DecentralizedRASession::SmartMsgEntryPoint(std::unique_ptr<Connection>& connection, EnclaveServiceProviderBase & hwEnclave, DecentralizedEnclave & enclave, const Json::Value & jsonMsg)
{
	const std::string inType = DecentralizedMessage::ParseType(jsonMsg[Messages::LABEL_ROOT]);
	if (inType == DecentralizedRAHandshake::VALUE_TYPE)
	{
		DecentralizedRAHandshake hsMsg(jsonMsg);
		DecentralizedRASession raSession(connection, hwEnclave, enclave, hsMsg);
		bool res = raSession.ProcessServerSideRA();
		raSession.SwapConnection(connection);
		return res;
	}
	else if (inType == DecentralizedRAHandshakeAck::VALUE_TYPE)
	{
		DecentralizedRAHandshakeAck ackMsg(jsonMsg);
		DecentralizedRASession raSession(connection, hwEnclave, enclave, ackMsg);
		bool res = raSession.ProcessClientSideRA();
		raSession.SwapConnection(connection);
		return res;
	}
	return false;
}

static const DecentralizedRAHandshakeAck SendAndReceiveHandshakeAck(std::unique_ptr<Connection>& connection, EnclaveServiceProviderBase& enclave)
{
	DecentralizedRASession::SendHandshakeMessage(connection, enclave);

	Json::Value jsonMsg;
	connection->Receive(jsonMsg);

	return DecentralizedRAHandshakeAck(jsonMsg);
}

DecentralizedRASession::DecentralizedRASession(std::unique_ptr<Connection>& connection, EnclaveServiceProviderBase& hwEnclave, DecentralizedEnclave& enclave) :
	DecentralizedRASession(connection, hwEnclave, enclave, SendAndReceiveHandshakeAck(connection, hwEnclave))
{
}

DecentralizedRASession::DecentralizedRASession(std::unique_ptr<Connection>& connection, EnclaveServiceProviderBase & hwEnclave, DecentralizedEnclave & enclave, const DecentralizedRAHandshake & hsMsg) :
	m_hwEnclave(hwEnclave),
	k_senderID(ConstructSenderID(hwEnclave)),
	k_remoteSideID(hsMsg.GetSenderID()),
	m_decentralizedEnc(enclave),
	k_isServerSide(true)
{
	m_connection.swap(connection);

	m_connection->Send(DecentralizedRAHandshakeAck(k_senderID));
}

DecentralizedRASession::DecentralizedRASession(std::unique_ptr<Connection>& connection, EnclaveServiceProviderBase & hwEnclave, DecentralizedEnclave & enclave, const DecentralizedRAHandshakeAck & ackMsg) :
	m_hwEnclave(hwEnclave),
	k_senderID(ConstructSenderID(hwEnclave)),
	k_remoteSideID(ackMsg.GetSenderID()),
	m_decentralizedEnc(enclave),
	k_isServerSide(false)
{
	m_connection.swap(connection);
}

DecentralizedRASession::~DecentralizedRASession()
{
}

bool DecentralizedRASession::ProcessClientSideRA()
{
	if (!m_connection || k_isServerSide)
	{
		return false;
	}

	bool res = true;

	try
	{
		std::shared_ptr<ClientRASession> clientSession = m_hwEnclave.GetRAClientSession(m_connection);
		res = clientSession->ProcessClientSideRA();
		clientSession->SwapConnection(m_connection);

		if (!res)
		{
			return res;
		}

		SendReverseRARequest(k_senderID); //should reture true here since the m_connection is available at this point.

		std::shared_ptr<ServiceProviderRASession> spSession = m_hwEnclave.GetRASPSession(m_connection);
		res = spSession->ProcessServerSideRA();
		spSession->SwapConnection(m_connection);

		if (!res)
		{
			return res;
		}

		RecvReverseRARequest();
		m_decentralizedEnc.ToDecentralizedNode(k_remoteSideID, k_isServerSide);

		return true;
	}
	catch (const MessageParseException&)
	{
		DecentralizedErrMsg errMsg(k_senderID, "Received unexpected message! Make sure you are following the protocol.");
		m_connection->Send(errMsg);
		return false;
	}
}

bool DecentralizedRASession::ProcessServerSideRA()
{
	if (!m_connection || !k_isServerSide)
	{
		return false;
	}

	bool res = true;

	try
	{
		std::shared_ptr<ServiceProviderRASession> spSession = m_hwEnclave.GetRASPSession(m_connection);
		res = spSession->ProcessServerSideRA();
		spSession->SwapConnection(m_connection);

		if (!res)
		{
			return res;
		}

		RecvReverseRARequest(); //should reture true here since the m_connection is available at this point.

		std::shared_ptr<ClientRASession> clientSession = m_hwEnclave.GetRAClientSession(m_connection);
		res = clientSession->ProcessClientSideRA();
		clientSession->SwapConnection(m_connection);

		if (!res)
		{
			return res;
		}

		SendReverseRARequest(k_senderID);
		m_decentralizedEnc.ToDecentralizedNode(k_remoteSideID, k_isServerSide);

		return true;
	}
	catch (const MessageParseException&)
	{
		DecentralizedErrMsg errMsg(k_senderID, "Received unexpected message! Make sure you are following the protocol.");
		m_connection->Send(errMsg);
		return false;
	}
}

bool DecentralizedRASession::SendReverseRARequest(const std::string & senderID)
{
	if (!m_connection)
	{
		return false;
	}

	m_connection->Send(DecentralizedReverseReq(senderID));

	return true;
}

bool DecentralizedRASession::RecvReverseRARequest()
{
	if (!m_connection)
	{
		return false;
	}

	std::string msgBuffer;
	m_connection->Receive(msgBuffer);

	delete ParseMessageExpected<DecentralizedReverseReq>(msgBuffer);

	return true;
}
