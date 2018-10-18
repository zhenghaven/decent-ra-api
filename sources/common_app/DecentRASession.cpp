#include "DecentRASession.h"

#include <map>

#include <json/json.h>

#include <sgx_tcrypto.h>

#include "EnclaveServiceProviderBase.h"
#include "DecentEnclave.h"

#include "ClientRASession.h"
#include "ServiceProviderRASession.h"

#include "DecentMessages/DecentMessage.h"
#include "MessageException.h"

#include "Networking/Connection.h"
#include "Logger/LoggerManager.h"

#include "../common/DataCoding.h"

static inline std::string ConstructSenderID(EnclaveServiceProviderBase & enclave)
{
	sgx_ec256_public_t signPubKey;
	enclave.GetRAClientSignPubKey(signPubKey);
	return SerializeStruct(signPubKey);
}

void DecentRASession::SendHandshakeMessage(Connection& connection, EnclaveServiceProviderBase & enclave)
{
	connection.SendPack(DecentRAHandshake(ConstructSenderID(enclave)));
}

bool DecentRASession::SmartMsgEntryPoint(Connection& connection, EnclaveServiceProviderBase & hwEnclave, DecentEnclave & enclave, const Json::Value & jsonMsg)
{
	const std::string inType = DecentMessage::ParseType(jsonMsg[Messages::sk_LabelRoot]);
	if (inType == DecentRAHandshake::sk_ValueType)
	{
		DecentRAHandshake hsMsg(jsonMsg);
		std::unique_ptr<DecentLogger> logger(std::make_unique<DecentLogger>(hsMsg.GetSenderID()));
		logger->AddMessage('I', "Received Decent Join Request.");
		DecentRASession raSession(connection, hwEnclave, enclave, hsMsg);
		bool res = raSession.ProcessServerSideRA(logger.get());
		logger->AddMessage('I', "Completed Processing Decent Join Request.");
		DecentLoggerManager::GetInstance().AddLogger(logger);
		return res;
	}
	else if (inType == DecentRAHandshakeAck::sk_ValueType)
	{
		DecentRAHandshakeAck ackMsg(jsonMsg);
		DecentRASession raSession(connection, hwEnclave, enclave, ackMsg);
		bool res = raSession.ProcessClientSideRA();
		return res;
	}
	return false;
}

static const DecentRAHandshakeAck SendAndReceiveHandshakeAck(Connection& connection, EnclaveServiceProviderBase& enclave)
{
	DecentRASession::SendHandshakeMessage(connection, enclave);

	Json::Value jsonMsg;
	connection.ReceivePack(jsonMsg);
	
	return DecentRAHandshakeAck(jsonMsg);
}

DecentRASession::DecentRASession(Connection& connection, EnclaveServiceProviderBase& hwEnclave, DecentEnclave& enclave) :
	DecentRASession(connection, hwEnclave, enclave, SendAndReceiveHandshakeAck(connection, hwEnclave))
{
}

DecentRASession::DecentRASession(Connection& connection, EnclaveServiceProviderBase & hwEnclave, DecentEnclave & enclave, const DecentRAHandshake & hsMsg) :
	CommSession(connection),
	k_senderId(ConstructSenderID(hwEnclave)),
	k_remoteSideId(hsMsg.GetSenderID()),
	m_hwEnclave(hwEnclave),
	m_decentEnclave(enclave),
	k_isServerSide(true)
{
	connection.SendPack(DecentRAHandshakeAck(k_senderId, enclave.GetDecentSelfRAReport()));
}

DecentRASession::DecentRASession(Connection& connection, EnclaveServiceProviderBase & hwEnclave, DecentEnclave & enclave, const DecentRAHandshakeAck & ackMsg) :
	CommSession(connection),
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
}

DecentRASession::~DecentRASession()
{
}

bool DecentRASession::ProcessClientSideRA(DecentLogger* logger)
{
	if (k_isServerSide)
	{
		return false;
	}

	bool res = true;

	std::unique_ptr<ClientRASession> clientSession(m_hwEnclave.GetRAClientSession(m_connection));
	res = clientSession->ProcessClientSideRA();

	if (!res)
	{
		return false;
	}

	m_connection.SendPack(DecentProtocolKeyReq(k_senderId));

	res = m_decentEnclave.ProcessDecentProtoKeyMsg(k_remoteSideId, m_connection);

	return false;
}

bool DecentRASession::ProcessServerSideRA(DecentLogger* logger)
{
	if (!k_isServerSide)
	{
		return false;
	}

	bool res = true;

	std::unique_ptr<ServiceProviderRASession> spSession(m_hwEnclave.GetRASPSession(m_connection));
	res = spSession->ProcessServerSideRA();
	if (!res)
	{
		return false;
	}

	Json::Value keyReqJson;
	m_connection.ReceivePack(keyReqJson);
	DecentProtocolKeyReq keyReq(keyReqJson);

	res = m_decentEnclave.SendProtocolKey(keyReq.GetSenderID(), m_connection);
	if (res && logger)
	{
		logger->AddMessage('I', "New Node Attested Successfully!");
	}
	else if (logger)
	{
		logger->AddMessage('I', "New Node Failed Attestion!");
	}
	return false;
}
