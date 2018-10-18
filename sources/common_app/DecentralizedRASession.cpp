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

	if (DecentralizedMessage::ParseType(json[Messages::sk_LabelRoot]) == DecentralizedErrMsg::sk_ValueType)
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

void DecentralizedRASession::SendHandshakeMessage(Connection& connection, EnclaveServiceProviderBase & enclave)
{
	DecentralizedRAHandshake msg0s(enclave.GetRAClientSignPubKey());
	connection.SendPack(msg0s);
}

bool DecentralizedRASession::SmartMsgEntryPoint(Connection& connection, EnclaveServiceProviderBase & hwEnclave, DecentralizedEnclave & enclave, const Json::Value & jsonMsg)
{
	const std::string inType = DecentralizedMessage::ParseType(jsonMsg[Messages::sk_LabelRoot]);
	if (inType == DecentralizedRAHandshake::sk_ValueType)
	{
		DecentralizedRAHandshake hsMsg(jsonMsg);
		DecentralizedRASession raSession(connection, hwEnclave, enclave, hsMsg);
		bool res = raSession.ProcessServerSideRA();
		return res;
	}
	else if (inType == DecentralizedRAHandshakeAck::sk_ValueType)
	{
		DecentralizedRAHandshakeAck ackMsg(jsonMsg);
		DecentralizedRASession raSession(connection, hwEnclave, enclave, ackMsg);
		bool res = raSession.ProcessClientSideRA();
		return res;
	}
	return false;
}

static const DecentralizedRAHandshakeAck SendAndReceiveHandshakeAck(Connection& connection, EnclaveServiceProviderBase& enclave)
{
	DecentralizedRASession::SendHandshakeMessage(connection, enclave);

	Json::Value jsonMsg;
	connection.ReceivePack(jsonMsg);

	return DecentralizedRAHandshakeAck(jsonMsg);
}

DecentralizedRASession::DecentralizedRASession(Connection& connection, EnclaveServiceProviderBase& hwEnclave, DecentralizedEnclave& enclave) :
	DecentralizedRASession(connection, hwEnclave, enclave, SendAndReceiveHandshakeAck(connection, hwEnclave))
{
}

DecentralizedRASession::DecentralizedRASession(Connection& connection, EnclaveServiceProviderBase & hwEnclave, DecentralizedEnclave & enclave, const DecentralizedRAHandshake & hsMsg) :
	CommSession(connection),
	m_hwEnclave(hwEnclave),
	k_senderId(hwEnclave.GetRAClientSignPubKey()),
	k_remoteSideId(hsMsg.GetSenderID()),
	m_decentralizedEnc(enclave),
	k_isServerSide(true)
{
	connection.SendPack(DecentralizedRAHandshakeAck(k_senderId));

}

DecentralizedRASession::DecentralizedRASession(Connection& connection, EnclaveServiceProviderBase & hwEnclave, DecentralizedEnclave & enclave, const DecentralizedRAHandshakeAck & ackMsg) :
	CommSession(connection),
	m_hwEnclave(hwEnclave),
	k_senderId(hwEnclave.GetRAClientSignPubKey()),
	k_remoteSideId(ackMsg.GetSenderID()),
	m_decentralizedEnc(enclave),
	k_isServerSide(false)
{
}

DecentralizedRASession::~DecentralizedRASession()
{
}

bool DecentralizedRASession::ProcessClientSideRA()
{
	if (k_isServerSide)
	{
		return false;
	}

	bool res = true;

	try
	{
		std::unique_ptr<ClientRASession> clientSession(m_hwEnclave.GetRAClientSession(m_connection));
		res = clientSession->ProcessClientSideRA();

		if (!res)
		{
			return res;
		}

		SendReverseRARequest(k_senderId); //should reture true here since the m_connection is available at this point.

		std::unique_ptr<ServiceProviderRASession> spSession(m_hwEnclave.GetRASPSession(m_connection));
		res = spSession->ProcessServerSideRA();

		if (!res)
		{
			return res;
		}

		RecvReverseRARequest();
		m_decentralizedEnc.ToDecentralizedNode(k_remoteSideId, k_isServerSide);

		return true;
	}
	catch (const MessageParseException&)
	{
		DecentralizedErrMsg errMsg(k_senderId, "Received unexpected message! Make sure you are following the protocol.");
		m_connection.SendPack(errMsg);
		return false;
	}
}

bool DecentralizedRASession::ProcessServerSideRA()
{
	if (!k_isServerSide)
	{
		return false;
	}

	bool res = true;

	try
	{
		std::unique_ptr<ServiceProviderRASession> spSession(m_hwEnclave.GetRASPSession(m_connection));
		res = spSession->ProcessServerSideRA();

		if (!res)
		{
			return res;
		}

		RecvReverseRARequest(); //should reture true here since the m_connection is available at this point.

		std::unique_ptr<ClientRASession> clientSession(m_hwEnclave.GetRAClientSession(m_connection));
		res = clientSession->ProcessClientSideRA();

		if (!res)
		{
			return res;
		}

		SendReverseRARequest(k_senderId);
		m_decentralizedEnc.ToDecentralizedNode(k_remoteSideId, k_isServerSide);

		return true;
	}
	catch (const MessageParseException&)
	{
		DecentralizedErrMsg errMsg(k_senderId, "Received unexpected message! Make sure you are following the protocol.");
		m_connection.SendPack(errMsg);
		return false;
	}
}

bool DecentralizedRASession::SendReverseRARequest(const std::string & senderID)
{
	m_connection.SendPack(DecentralizedReverseReq(senderID));

	return true;
}

bool DecentralizedRASession::RecvReverseRARequest()
{
	std::string msgBuffer;
	m_connection.ReceivePack(msgBuffer);

	delete ParseMessageExpected<DecentralizedReverseReq>(msgBuffer);

	return true;
}
