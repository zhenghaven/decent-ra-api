#include "DecentRASession.h"

#include <cstring>
#include <map>

#include <json/json.h>

#include "Common.h"
#include "DecentEnclave.h"
#include "EnclaveBase.h"
#include "ClientRASession.h"

#include "DecentMessages/DecentMessage.h"

#include "Networking/Connection.h"
#include "../common/DataCoding.h"

DecentRASession::DecentRASession(std::unique_ptr<Connection>& connection, EnclaveBase& hardwareEnclave, ServiceProviderBase& sp, DecentEnclave & enclave) :
	DecentralizedRASession(connection, hardwareEnclave, sp, enclave),
	m_decentEnclave(enclave)
{
}

DecentRASession::~DecentRASession()
{
}

bool DecentRASession::ProcessClientSideRA()
{
	if (!m_connection)
	{
		return false;
	}

	bool res = true;

	res = DecentralizedRASession::ProcessClientSideRA();
	if (!res)
	{
		return false;
	}

	//res = ProcessClientSideKeyRequest();

	return res;
}

bool DecentRASession::ProcessServerSideRA()
{
	if (!m_connection)
	{
		return false;
	}
/*
	if (m_decentEnclave.GetDecentMode() == DecentNodeMode::APPL_SERVER)
	{
		return ProcessServerMessage0();
	}*/

	bool res = true;

	res = DecentralizedRASession::ProcessServerSideRA();
	if (!res)
	{
		return false;
	}

	//res = ProcessServerSideKeyRequest();

	return res;
}
//
//bool DecentRASession::ProcessClientSideKeyRequest()
//{
//	if (!m_connection)
//	{
//		return false;
//	}
//
//	RAMessages* resp = nullptr;
//	std::string msgBuffer;
//	sgx_status_t enclaveRes = SGX_SUCCESS;
//	const std::string senderID = m_hardwareSession->GetSenderID();
//
//	sgx_ec256_public_t signKey;
//	sgx_ec256_public_t encrKey;
//
//	m_hardwareEnclave.GetRAClientSignPubKey(signKey);
//	//m_hardwareEnclave.GetRAClientEncrPubKey(encrKey);
//	DecentMessageKeyReq msgKR(senderID, m_decentEnclave.GetDecentMode(), signKey, encrKey);
//	m_connection->Send(msgKR.ToJsonString());
//
//	m_connection->Receive(msgBuffer);
//	resp = JsonMessageParser(msgBuffer);
//	if (resp->GetMessgaeSubTypeStr() == DecentMessage::GetMessageTypeStr(DecentMessage::Type::DECENT_ERROR_MSG))
//	{
//		return false;
//	}
//	switch (m_decentEnclave.GetDecentMode())
//	{
//	case DecentNodeMode::ROOT_SERVER:
//	{
//		DecentMessageRootResp* krResp = dynamic_cast<DecentMessageRootResp*>(resp);
//		if (!resp || !krResp || !krResp->IsValid())
//		{
//			delete resp;
//			return false;
//		}
//
//		enclaveRes = m_decentEnclave.SetProtocolSignKey(krResp->GetSenderID(), krResp->GetPriSignKey(), krResp->GetPriSignKeyMac(), krResp->GetPubSignKey(), krResp->GetPubSignKeyMac());
//		if (enclaveRes != SGX_SUCCESS)
//		{
//			delete resp;
//			return false;
//		}
//		
//		//enclaveRes = m_decentEnclave.SetProtocolEncrKey(krResp->GetSenderID(), krResp->GetPriEncrKey(), krResp->GetPriEncrKeyMac(), krResp->GetPubEncrKey(), krResp->GetPubEncrKeyMac());
//		//if (enclaveRes != SGX_SUCCESS)
//		//{
//		//	delete resp;
//		//	return false;
//		//}
//	}
//	break;
//	case DecentNodeMode::APPL_SERVER:
//	default:
//	{
//		DecentMessageApplResp* krResp = dynamic_cast<DecentMessageApplResp*>(resp);
//		if (!resp || !krResp || !krResp->IsValid())
//		{
//			delete resp;
//			return false;
//		}
//
//		enclaveRes = m_decentEnclave.SetKeySigns(krResp->GetSenderID(), krResp->GetSignSign(), krResp->GetSignMac(), krResp->GetEncrSign(), krResp->GetEncrMac());
//		if (enclaveRes != SGX_SUCCESS)
//		{
//			delete resp;
//			return false;
//		}
//		
//	}
//	break;
//	}
//
//	delete resp;
//	return true;
//}
//
//bool DecentRASession::ProcessServerSideKeyRequest()
//{
//	if (!m_connection)
//	{
//		return false;
//	}
//	if (m_decentEnclave.GetDecentMode() != DecentNodeMode::ROOT_SERVER)
//	{
//		return false;
//	}
//
//	sgx_status_t enclaveRes = SGX_SUCCESS;
//	const std::string senderID = m_hardwareSession->GetSenderID();
//
//	RAMessages* resp = nullptr;
//	std::string msgBuffer;
//	m_connection->Receive(msgBuffer);
//	resp = JsonMessageParser(msgBuffer);
//
//	DecentMessageKeyReq* msgKR = dynamic_cast<DecentMessageKeyReq*>(resp);
//	if (!resp || !msgKR || !msgKR->IsValid())
//	{
//		delete resp;
//		return false;
//	}
//
//	DecentMessage* krResp = nullptr;
//	switch (msgKR->GetMode())
//	{
//	case DecentNodeMode::ROOT_SERVER:
//	{
//		sgx_ec256_private_t priSignKey;
//		sgx_aes_gcm_128bit_tag_t priSignKeyMac;
//		sgx_ec256_public_t pubSignKey;
//		sgx_aes_gcm_128bit_tag_t pubSignKeyMac;
//		enclaveRes = m_decentEnclave.GetProtocolSignKey(msgKR->GetSenderID(), priSignKey, priSignKeyMac, pubSignKey, pubSignKeyMac);
//		if (enclaveRes != SGX_SUCCESS)
//		{
//			delete resp;
//			DecentMessageErr errMsg(senderID, "Enclave Process Error!");
//			m_connection->Send(errMsg.ToJsonString());
//			return false;
//		}
//
//		sgx_ec256_private_t priEncrKey;
//		sgx_aes_gcm_128bit_tag_t priEncrKeyMac;
//
//		krResp = new DecentMessageRootResp(senderID, priSignKey, priSignKeyMac, pubSignKey, pubSignKeyMac,
//			priEncrKey, priEncrKeyMac, pubEncrKey, pubEncrKeyMac);
//	}
//		break;
//	case DecentNodeMode::APPL_SERVER:
//	default:
//	{
//		sgx_ec256_signature_t signSign;
//		sgx_aes_gcm_128bit_tag_t signMac;
//		sgx_ec256_signature_t encrSign;
//		sgx_aes_gcm_128bit_tag_t encrMac;
//		enclaveRes = m_decentEnclave.GetProtocolKeySigned(msgKR->GetSenderID(), msgKR->GetSignKey(), msgKR->GetEncrKey(), signSign, signMac, encrSign, encrMac);
//
//		krResp = new DecentMessageApplResp(senderID, signSign, signMac, encrSign, encrMac);
//	}
//		break;
//	}
//	m_connection->Send(krResp->ToJsonString());
//	delete krResp;
//
//	delete resp;
//	resp = nullptr;
//	msgKR = nullptr;
//	return true;
//}
//
//DecentMessageMsg0* DecentRASession::ConstructMessage0()
//{
//	sgx_status_t enclaveRes = SGX_SUCCESS;
//	const std::string senderID = m_hardwareSession->GetSenderID();
//
//	sgx_ec256_public_t pubSignKey;
//	sgx_ec256_signature_t signSign;
//	sgx_ec256_public_t pubEncrKey;
//	sgx_ec256_signature_t encrSign;
//
//	m_hardwareEnclave.GetRAClientSignPubKey(pubSignKey);
//
//	//enclaveRes = m_hardwareEnclave.GetRAClientEncrPubKey(pubEncrKey);
//
//	//m_decentEnclave.GetKeySigns(signSign, encrSign);
//
//	//enclaveRes = (enclaveRes != SGX_SUCCESS) ? enclaveRes : decentEnc->GetLastStatus();
//
//	return (enclaveRes != SGX_SUCCESS) ? nullptr : new DecentMessageMsg0(senderID, pubSignKey, signSign, pubEncrKey, encrSign);
//}
//
//bool DecentRASession::ProcessClientMessage0()
//{
//	if (!m_connection)
//	{
//		return false;
//	}
//
//	sgx_status_t enclaveRes = SGX_SUCCESS;
//
//	DecentMessageMsg0* msg0Req = ConstructMessage0();
//	if (!msg0Req)
//	{
//		return false;
//	}
//
//	m_connection->Send(msg0Req->ToJsonString());
//	delete msg0Req;
//	msg0Req = nullptr;
//
//
//	RAMessages* resp = nullptr;
//	std::string msgBuffer;
//	m_connection->Receive(msgBuffer);
//	resp = JsonMessageParser(msgBuffer);
//
//	DecentMessageMsg0* msg0Resp = dynamic_cast<DecentMessageMsg0*>(resp);
//	if (!resp || !msg0Resp || !msg0Resp->IsValid())
//	{
//		delete resp;
//		return false;
//	}
//
//	enclaveRes = m_decentEnclave.ProcessDecentMsg0(msg0Resp->GetSenderID(), msg0Resp->GetSignKey(), msg0Resp->GetSignSign(), msg0Resp->GetEncrKey(), msg0Resp->GetEncrSign());
//	if (enclaveRes != SGX_SUCCESS)
//	{
//		delete resp;
//		return false;
//	}
//
//	delete resp;
//	resp = nullptr;
//	msg0Resp = nullptr;
//
//	return true;
//}
//
//bool DecentRASession::ProcessServerMessage0()
//{
//	if (!m_connection)
//	{
//		return false;
//	}
//
//	sgx_status_t enclaveRes = SGX_SUCCESS;
//	const std::string senderID = m_hardwareSession->GetSenderID();
//
//	RAMessages* resp = nullptr;
//	std::string msgBuffer;
//	m_connection->Receive(msgBuffer);
//	resp = JsonMessageParser(msgBuffer);
//
//	DecentMessageMsg0* msg0req = dynamic_cast<DecentMessageMsg0*>(resp);
//	if (!resp || !msg0req || !msg0req->IsValid())
//	{
//		delete resp;
//		DecentMessageErr errMsg(senderID, "Invalid Message!");
//		m_connection->Send(errMsg.ToJsonString());
//		return false;
//	}
//
//	enclaveRes = m_decentEnclave.ProcessDecentMsg0(msg0req->GetSenderID(), msg0req->GetSignKey(), msg0req->GetSignSign(), msg0req->GetEncrKey(), msg0req->GetEncrSign());
//	if (enclaveRes != SGX_SUCCESS)
//	{
//		delete resp;
//		DecentMessageErr errMsg(senderID, "Enclave Process Error!");
//		m_connection->Send(errMsg.ToJsonString());
//		return false;
//	}
//
//	delete resp;
//	resp = nullptr;
//	msg0req = nullptr;
//
//	DecentMessageMsg0* msg0Resp = ConstructMessage0();
//	if (!msg0Resp)
//	{
//		DecentMessageErr errMsg(senderID, "Enclave Process Error!");
//		m_connection->Send(errMsg.ToJsonString());
//		return false;
//	}
//
//	m_connection->Send(msg0Resp->ToJsonString());
//	delete msg0Resp;
//
//	return true;
//}
