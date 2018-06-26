#include "DecentRASession.h"

#include <cstring>
#include <map>

#include <json/json.h>

#include "Common.h"
#include "RAMessageRevRAReq.h"
#include "DecentEnclave.h"
#include "EnclaveBase.h"

#include "DecentMessages/DecentMessage.h"

#include "Networking/Connection.h"
#include "../common/CryptoTools.h"

#include "DecentMessages/DecentMessageMsg0.h"
#include "DecentMessages/DecentMessageKeyReq.h"
#include "DecentMessages/DecentMessageRootResp.h"
#include "DecentMessages/DecentMessageApplResp.h"
#include "DecentMessages/DecentMessageErr.h"

namespace 
{
	std::map<std::string, DecentMessage::Type> g_msgTypeNameMap =
	{
		std::pair<std::string, DecentMessage::Type>("DECENT_MSG0", DecentMessage::Type::DECENT_MSG0),
		std::pair<std::string, DecentMessage::Type>("DECENT_KEY_REQ", DecentMessage::Type::DECENT_KEY_REQ),
		std::pair<std::string, DecentMessage::Type>("ROOT_NODE_RESP", DecentMessage::Type::ROOT_NODE_RESP),
		std::pair<std::string, DecentMessage::Type>("APPL_NODE_RESP", DecentMessage::Type::APPL_NODE_RESP),
		std::pair<std::string, DecentMessage::Type>("DECENT_ERROR_MSG", DecentMessage::Type::DECENT_ERROR_MSG),
		std::pair<std::string, DecentMessage::Type>("OTHER", DecentMessage::Type::OTHER),
	};
}

static RAMessages * JsonMessageParser(const std::string& jsonStr)
{
	Json::Value jsonRoot;
	Json::CharReaderBuilder rbuilder;
	rbuilder["collectComments"] = false;
	std::string errStr;

	const std::unique_ptr<Json::CharReader> reader(rbuilder.newCharReader());
	bool isValid = reader->parse(jsonStr.c_str(), jsonStr.c_str() + jsonStr.size(), &jsonRoot, &errStr);

	if (!isValid
		|| !jsonRoot.isMember("MsgSubType")
		|| !jsonRoot["MsgSubType"].isString())
	{
		LOGI("Recv INVALID MESSAGE!");
		return nullptr;
	}

	if (jsonRoot["MsgSubType"].asString() == "ReverseRARequest")
	{
		return new RAMessageRevRAReq(jsonRoot);
	}

	auto it = g_msgTypeNameMap.find(jsonRoot["MsgSubType"].asString());
	if (it == g_msgTypeNameMap.end() || it->second == DecentMessage::Type::OTHER)
	{
		LOGI("Recv INVALID MESSAGE!");
		return nullptr;
	}

	switch (it->second)
	{
	case DecentMessage::Type::DECENT_MSG0:
		return new DecentMessageMsg0(jsonRoot);
	case DecentMessage::Type::DECENT_KEY_REQ:
		return new DecentMessageKeyReq(jsonRoot);
	case DecentMessage::Type::ROOT_NODE_RESP:
		return new DecentMessageRootResp(jsonRoot);
	case DecentMessage::Type::APPL_NODE_RESP:
		return new DecentMessageApplResp(jsonRoot);
	case DecentMessage::Type::DECENT_ERROR_MSG:
		return new DecentMessageErr(jsonRoot);
	default:
		return nullptr;
	}
}

DecentRASession::~DecentRASession()
{
}

bool DecentRASession::SendReverseRARequest(const std::string& senderID)
{
	if (!m_connection)
	{
		return false;
	}

	RAMessageRevRAReq msg(senderID);
	m_connection->Send(msg.ToJsonString());

	return true;
}

bool DecentRASession::RecvReverseRARequest()
{
	if (!m_connection)
	{
		return false;
	}

	RAMessages* resp = nullptr;
	std::string msgBuffer;
	m_connection->Receive(msgBuffer);
	resp = JsonMessageParser(msgBuffer); 

	RAMessageRevRAReq* revReq = dynamic_cast<RAMessageRevRAReq*>(resp);
	if (!resp || !revReq || !revReq->IsValid())
	{
		delete resp;
		return false;
	}

	delete resp;
	resp = nullptr;
	revReq = nullptr;

	return true;
}

//bool DecentRASession::ProcessClientSideRA(EnclaveBase & enclave)
//{
//
//	return true;
//}
//
//bool DecentRASession::ProcessServerSideRA(EnclaveBase & enclave)
//{
//
//	return true;
//}

bool DecentRASession::ProcessClientSideKeyRequest(DecentEnclave & enclave)
{
	if (!m_connection)
	{
		return false;
	}
	//TODO: Simplify this later:
	DecentEnclave* decentEnc = dynamic_cast<DecentEnclave*>(&enclave);
	if (!decentEnc)
	{
		return false;
	}
	RAMessages* resp = nullptr;
	std::string msgBuffer;
	sgx_status_t enclaveRes = SGX_SUCCESS;
	const std::string senderID = static_cast<const DecentEnclave&>(enclave).GetEnclaveHardware()->GetRASenderID();

	sgx_ec256_public_t signKey;
	sgx_ec256_public_t encrKey;

	decentEnc->GetEnclaveHardware()->GetRASignPubKey(signKey);
	decentEnc->GetEnclaveHardware()->GetRAEncrPubKey(encrKey);
	DecentMessageKeyReq msgKR(senderID, decentEnc->GetDecentMode(), signKey, encrKey);
	m_connection->Send(msgKR.ToJsonString());

	m_connection->Receive(msgBuffer);
	resp = JsonMessageParser(msgBuffer);
	if (resp->GetMessgaeSubTypeStr() == DecentMessage::GetMessageTypeStr(DecentMessage::Type::DECENT_ERROR_MSG))
	{
		return false;
	}
	switch (decentEnc->GetDecentMode())
	{
	case DecentNodeMode::ROOT_SERVER:
	{
		DecentMessageRootResp* krResp = dynamic_cast<DecentMessageRootResp*>(resp);
		if (!resp || !krResp || !krResp->IsValid())
		{
			delete resp;
			return false;
		}

		enclaveRes = decentEnc->SetProtocolSignKey(krResp->GetSenderID(), krResp->GetPriSignKey(), krResp->GetPriSignKeyMac(), krResp->GetPubSignKey(), krResp->GetPubSignKeyMac());
		if (enclaveRes != SGX_SUCCESS)
		{
			delete resp;
			return false;
		}
		
		enclaveRes = decentEnc->SetProtocolEncrKey(krResp->GetSenderID(), krResp->GetPriEncrKey(), krResp->GetPriEncrKeyMac(), krResp->GetPubEncrKey(), krResp->GetPubEncrKeyMac());
		if (enclaveRes != SGX_SUCCESS)
		{
			delete resp;
			return false;
		}
	}
	break;
	case DecentNodeMode::APPL_SERVER:
	default:
	{
		DecentMessageApplResp* krResp = dynamic_cast<DecentMessageApplResp*>(resp);
		if (!resp || !krResp || !krResp->IsValid())
		{
			delete resp;
			return false;
		}

		enclaveRes = decentEnc->SetKeySigns(krResp->GetSenderID(), krResp->GetSignSign(), krResp->GetSignMac(), krResp->GetEncrSign(), krResp->GetEncrMac());
		if (enclaveRes != SGX_SUCCESS)
		{
			delete resp;
			return false;
		}
		
	}
	break;
	}

	delete resp;
	return true;
}

bool DecentRASession::ProcessServerSideKeyRequest(DecentEnclave & enclave)
{
	if (!m_connection)
	{
		return false;
	}
	if (enclave.GetDecentMode != DecentNodeMode::ROOT_SERVER)
	{
		return false;
	}
	DecentEnclave* decentEnc = dynamic_cast<DecentEnclave*>(&enclave);
	if (!decentEnc)
	{
		return false;
	}
	sgx_status_t enclaveRes = SGX_SUCCESS;
	const std::string senderID = static_cast<const DecentEnclave&>(enclave).GetEnclaveHardware()->GetRASenderID();

	RAMessages* resp = nullptr;
	std::string msgBuffer;
	m_connection->Receive(msgBuffer);
	resp = JsonMessageParser(msgBuffer);

	DecentMessageKeyReq* msgKR = dynamic_cast<DecentMessageKeyReq*>(resp);
	if (!resp || !msgKR || !msgKR->IsValid())
	{
		delete resp;
		return false;
	}

	DecentMessage* krResp = nullptr;
	switch (msgKR->GetMode())
	{
	case DecentNodeMode::ROOT_SERVER:
	{
		sgx_ec256_private_t priSignKey;
		sgx_aes_gcm_128bit_tag_t priSignKeyMac;
		sgx_ec256_public_t pubSignKey;
		sgx_aes_gcm_128bit_tag_t pubSignKeyMac;
		enclaveRes = decentEnc->GetProtocolSignKey(msgKR->GetSenderID(), priSignKey, priSignKeyMac, pubSignKey, pubSignKeyMac);
		if (enclaveRes != SGX_SUCCESS)
		{
			delete resp;
			DecentMessageErr errMsg(senderID, "Enclave Process Error!");
			m_connection->Send(errMsg.ToJsonString());
			return false;
		}

		sgx_ec256_private_t priEncrKey;
		sgx_aes_gcm_128bit_tag_t priEncrKeyMac;
		sgx_ec256_public_t pubEncrKey;
		sgx_aes_gcm_128bit_tag_t pubEncrKeyMac;
		enclaveRes = decentEnc->GetProtocolEncrKey(msgKR->GetSenderID(), priEncrKey, priEncrKeyMac, pubEncrKey, pubEncrKeyMac);
		if (enclaveRes != SGX_SUCCESS)
		{
			delete resp;
			DecentMessageErr errMsg(senderID, "Enclave Process Error!");
			m_connection->Send(errMsg.ToJsonString());
			return false;
		}

		krResp = new DecentMessageRootResp(senderID, priSignKey, priSignKeyMac, pubSignKey, pubSignKeyMac,
			priEncrKey, priEncrKeyMac, pubEncrKey, pubEncrKeyMac);
	}
		break;
	case DecentNodeMode::APPL_SERVER:
	default:
	{
		sgx_ec256_signature_t signSign;
		sgx_aes_gcm_128bit_tag_t signMac;
		sgx_ec256_signature_t encrSign;
		sgx_aes_gcm_128bit_tag_t encrMac;
		enclaveRes = decentEnc->GetProtocolKeySigned(msgKR->GetSenderID(), msgKR->GetSignKey(), msgKR->GetEncrKey(), signSign, signMac, encrSign, encrMac);

		krResp = new DecentMessageApplResp(senderID, signSign, signMac, encrSign, encrMac);
	}
		break;
	}
	m_connection->Send(krResp->ToJsonString());
	delete krResp;

	delete resp;
	resp = nullptr;
	msgKR = nullptr;
	return true;
}

DecentMessageMsg0* ConstructMessage0(DecentEnclave* decentEnc)
{
	sgx_status_t enclaveRes = SGX_SUCCESS;
	const std::string senderID = static_cast<const DecentEnclave*>(decentEnc)->GetEnclaveHardware()->GetRASenderID();

	sgx_ec256_public_t pubSignKey;
	sgx_ec256_signature_t signSign;
	sgx_ec256_public_t pubEncrKey;
	sgx_ec256_signature_t encrSign;

	enclaveRes = decentEnc->GetEnclaveHardware()->GetRASignPubKey(pubSignKey);

	enclaveRes = (enclaveRes != SGX_SUCCESS) ? enclaveRes : decentEnc->GetEnclaveHardware()->GetRAEncrPubKey(pubEncrKey);

	decentEnc->GetKeySigns(signSign, encrSign);

	//enclaveRes = (enclaveRes != SGX_SUCCESS) ? enclaveRes : decentEnc->GetLastStatus();

	return (enclaveRes != SGX_SUCCESS) ? nullptr : new DecentMessageMsg0(senderID, pubSignKey, signSign, pubEncrKey, encrSign);
}

bool DecentRASession::ProcessClientMessage0(DecentEnclave & enclave)
{
	if (!m_connection)
	{
		return false;
	}
	DecentEnclave* decentEnc = dynamic_cast<DecentEnclave*>(&enclave);
	if (!decentEnc)
	{
		return false;
	}
	sgx_status_t enclaveRes = SGX_SUCCESS;

	DecentMessageMsg0* msg0Req = ConstructMessage0(decentEnc);
	if (!msg0Req)
	{
		return false;
	}

	m_connection->Send(msg0Req->ToJsonString());
	delete msg0Req;
	msg0Req = nullptr;


	RAMessages* resp = nullptr;
	std::string msgBuffer;
	m_connection->Receive(msgBuffer);
	resp = JsonMessageParser(msgBuffer);

	DecentMessageMsg0* msg0Resp = dynamic_cast<DecentMessageMsg0*>(resp);
	if (!resp || !msg0Resp || !msg0Resp->IsValid())
	{
		delete resp;
		return false;
	}

	enclaveRes = decentEnc->ProcessDecentMsg0(msg0Resp->GetSenderID(), msg0Resp->GetSignKey(), msg0Resp->GetSignSign(), msg0Resp->GetEncrKey(), msg0Resp->GetEncrSign());
	if (enclaveRes != SGX_SUCCESS)
	{
		delete resp;
		return false;
	}

	delete resp;
	resp = nullptr;
	msg0Resp = nullptr;

	return true;
}

bool DecentRASession::ProcessServerMessage0(DecentEnclave & enclave)
{
	if (!m_connection)
	{
		return false;
	}
	DecentEnclave* decentEnc = dynamic_cast<DecentEnclave*>(&enclave);
	if (!decentEnc)
	{
		return false;
	}
	sgx_status_t enclaveRes = SGX_SUCCESS;
	const std::string senderID = static_cast<const DecentEnclave&>(enclave).GetEnclaveHardware()->GetRASenderID();

	RAMessages* resp = nullptr;
	std::string msgBuffer;
	m_connection->Receive(msgBuffer);
	resp = JsonMessageParser(msgBuffer);

	DecentMessageMsg0* msg0req = dynamic_cast<DecentMessageMsg0*>(resp);
	if (!resp || !msg0req || !msg0req->IsValid())
	{
		delete resp;
		DecentMessageErr errMsg(senderID, "Invalid Message!");
		m_connection->Send(errMsg.ToJsonString());
		return false;
	}

	enclaveRes = decentEnc->ProcessDecentMsg0(msg0req->GetSenderID(), msg0req->GetSignKey(), msg0req->GetSignSign(), msg0req->GetEncrKey(), msg0req->GetEncrSign());
	if (enclaveRes != SGX_SUCCESS)
	{
		delete resp;
		DecentMessageErr errMsg(senderID, "Enclave Process Error!");
		m_connection->Send(errMsg.ToJsonString());
		return false;
	}

	delete resp;
	resp = nullptr;
	msg0req = nullptr;

	DecentMessageMsg0* msg0Resp = ConstructMessage0(decentEnc);
	if (!msg0Resp)
	{
		DecentMessageErr errMsg(senderID, "Enclave Process Error!");
		m_connection->Send(errMsg.ToJsonString());
		return false;
	}

	m_connection->Send(msg0Resp->ToJsonString());
	delete msg0Resp;

	return true;
}
