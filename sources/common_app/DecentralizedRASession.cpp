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
#include "Networking/Connection.h"

template<class T>
static T*  ParseMessageExpected(const Json::Value& json)
{
	static_assert(std::is_base_of<DecentralizedMessage, T>::value, "Class type must be a child class of DecentralizedMessage.");
	try
	{
		std::string cat = DecentralizedMessage::ParseCat(json);
		if (cat != DecentralizedMessage::VALUE_CAT)
		{
			return nullptr;
		}

		std::string type = DecentralizedMessage::ParseType(json[Messages::LABEL_ROOT]);

		if (type == DecentralizedErrMsg::VALUE_TYPE)
		{
			throw ReceivedErrorMessageException();
		}

		if (type == T::VALUE_TYPE)
		{
			T* msgPtr = new T(json);
			return msgPtr;
		}
		else
		{
			return nullptr;
		}
	}
	catch (const MessageParseException& e)
	{
		LOGI("Caught Exception: %s\n", e.what());
		return nullptr;
	}
}

template<class T>
static T* ParseMessageExpected(const std::string& jsonStr)
{
	static_assert(std::is_base_of<DecentralizedMessage, T>::value, "Class type must be a child class of DecentralizedMessage.");

	Json::Value jsonRoot;
	Connection::ConvertMsgStr2Json(jsonRoot, jsonStr);

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

	DecentralizedRAHandshakeAck hsAck(k_senderID);
	m_connection->Send(hsAck.ToJsonString());
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

	std::shared_ptr<ClientRASession> clientSession = m_hwEnclave.GetRAClientSession(m_connection);
	res = clientSession->ProcessClientSideRA();
	clientSession->SwapConnection(m_connection);

	if (!res)
	{
		return res;
	}

	res = SendReverseRARequest(k_senderID);
	if (!res)
	{
		return res;
	}

	std::shared_ptr<ServiceProviderRASession> spSession = m_hwEnclave.GetRASPSession(m_connection);
	res = spSession->ProcessServerSideRA();
	spSession->SwapConnection(m_connection);

	if (!res)
	{
		return res;
	}

	res = RecvReverseRARequest();
	m_decentralizedEnc.ToDecentralizedNode(k_remoteSideID, k_isServerSide);

	return res;
}

bool DecentralizedRASession::ProcessServerSideRA()
{
	if (!m_connection || !k_isServerSide)
	{
		return false;
	}

	bool res = true;

	std::shared_ptr<ServiceProviderRASession> spSession = m_hwEnclave.GetRASPSession(m_connection);
	res = spSession->ProcessServerSideRA();
	spSession->SwapConnection(m_connection);

	if (!res)
	{
		return res;
	}

	res = RecvReverseRARequest();
	if (!res)
	{
		return res;
	}

	std::shared_ptr<ClientRASession> clientSession = m_hwEnclave.GetRAClientSession(m_connection);
	res = clientSession->ProcessClientSideRA();
	clientSession->SwapConnection(m_connection);

	if (!res)
	{
		return res;
	}

	res = SendReverseRARequest(k_senderID);
	m_decentralizedEnc.ToDecentralizedNode(k_remoteSideID, k_isServerSide);

	return res;
}

bool DecentralizedRASession::SendReverseRARequest(const std::string & senderID)
{
	if (!m_connection)
	{
		return false;
	}

	DecentralizedReverseReq msg(senderID);
	m_connection->Send(msg.ToJsonString());

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

	auto reqMsg = ParseMessageExpected<DecentralizedReverseReq>(msgBuffer);
	delete reqMsg;

	return true;
}
