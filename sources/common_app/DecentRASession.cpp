#include "DecentRASession.h"

#include <map>

#include <json/json.h>

#include <sgx_tcrypto.h>

#include "Common.h"

#include "EnclaveServiceProviderBase.h"
#include "DecentEnclave.h"

#include "ClientRASession.h"
#include "ServiceProviderRASession.h"

#include "DecentMessages/DecentMessage.h"
#include "MessageException.h"

#include "Networking/Connection.h"
#include "../common/DataCoding.h"

static inline std::string ConstructSenderID(EnclaveServiceProviderBase & enclave)
{
	sgx_ec256_public_t signPubKey;
	enclave.GetRAClientSignPubKey(signPubKey);
	return SerializeStruct(signPubKey);
}

void DecentRASession::SendHandshakeMessage(std::unique_ptr<Connection>& connection, EnclaveServiceProviderBase & enclave)
{
	DecentRAHandshake hs(ConstructSenderID(enclave));
	connection->Send(hs.ToJsonString());
}

bool DecentRASession::SmartMsgEntryPoint(std::unique_ptr<Connection>& connection, EnclaveServiceProviderBase & hwEnclave, DecentEnclave & enclave, const Json::Value & jsonMsg)
{
	const std::string inType = DecentMessage::ParseType(jsonMsg[Messages::sk_LabelRoot]);
	if (inType == DecentRAHandshake::sk_ValueType)
	{
		DecentRAHandshake hsMsg(jsonMsg);
		DecentRASession raSession(connection, hwEnclave, enclave, hsMsg);
		bool res = raSession.ProcessServerSideRA();
		raSession.SwapConnection(connection);
		return res;
	}
	else if (inType == DecentRAHandshakeAck::sk_ValueType)
	{
		DecentRAHandshakeAck ackMsg(jsonMsg);
		DecentRASession raSession(connection, hwEnclave, enclave, ackMsg);
		bool res = raSession.ProcessClientSideRA();
		raSession.SwapConnection(connection);
		return res;
	}
	return false;
}

static const DecentRAHandshakeAck SendAndReceiveHandshakeAck(std::unique_ptr<Connection>& connection, EnclaveServiceProviderBase& enclave)
{
	DecentRASession::SendHandshakeMessage(connection, enclave);

	Json::Value jsonMsg;
	connection->Receive(jsonMsg);
	
	return DecentRAHandshakeAck(jsonMsg);
}

DecentRASession::DecentRASession(std::unique_ptr<Connection>& connection, EnclaveServiceProviderBase& hwEnclave, DecentEnclave& enclave) :
	DecentRASession(connection, hwEnclave, enclave, SendAndReceiveHandshakeAck(connection, hwEnclave))
{
}

DecentRASession::DecentRASession(std::unique_ptr<Connection>& connection, EnclaveServiceProviderBase & hwEnclave, DecentEnclave & enclave, const DecentRAHandshake & hsMsg) :
	k_senderId(ConstructSenderID(hwEnclave)),
	k_remoteSideId(hsMsg.GetSenderID()),
	m_hwEnclave(hwEnclave),
	m_decentEnclave(enclave),
	k_isServerSide(true)
{
	DecentRAHandshakeAck hsAck(k_senderId, enclave.GetDecentSelfRAReport());
	connection->Send(hsAck.ToJsonString());

	m_connection.swap(connection);
}

DecentRASession::DecentRASession(std::unique_ptr<Connection>& connection, EnclaveServiceProviderBase & hwEnclave, DecentEnclave & enclave, const DecentRAHandshakeAck & ackMsg) :
	k_senderId(ConstructSenderID(hwEnclave)),
	k_remoteSideId(ackMsg.GetSenderID()),
	m_hwEnclave(hwEnclave),
	m_decentEnclave(enclave),
	k_isServerSide(false)
{
	if (!enclave.ProcessDecentSelfRAReport(ackMsg.GetSelfRAReport()))
	{
		throw MessageInvalidException();
	}

	m_connection.swap(connection);
}

DecentRASession::~DecentRASession()
{
}

bool DecentRASession::ProcessClientSideRA()
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
			return false;
		}

		DecentProtocolKeyReq keyReq(k_senderId);
		m_connection->Send(keyReq.ToJsonString());

		Json::Value trustedMsgJson;
		m_connection->Receive(trustedMsgJson);

		DecentTrustedMessage trustedMsg(trustedMsgJson);
		m_decentEnclave.ProcessDecentProtoKeyMsg(k_remoteSideId, m_connection, trustedMsg.GetTrustedMsg());

		return false;
	}
	catch (const MessageParseException&)
	{
		DecentErrMsg errMsg(k_senderId, "Received unexpected message! Make sure you are following the protocol.");
		m_connection->Send(errMsg);
		return false;
	}
}

bool DecentRASession::ProcessServerSideRA()
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
			return false;
		}

		Json::Value keyReqJson;
		m_connection->Receive(keyReqJson);
		DecentProtocolKeyReq keyReq(keyReqJson);

		m_decentEnclave.SendProtocolKey(keyReq.GetSenderID(), m_connection);

		return false;
	}
	catch (const std::exception&)
	{
		DecentErrMsg errMsg(k_senderId, "Received unexpected message! Make sure you are following the protocol.");
		m_connection->Send(errMsg);
		return false;
	}
}
