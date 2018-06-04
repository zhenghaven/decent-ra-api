#include "SGXRemoteAttestationSession.h"

#include <cstring>
#include <map>

#include <json/json.h>

#include "Common.h"
#include "SGXEnclave.h"
#include "SGXRAMessages/SGXRAMessage.h"
#include "SGXRAMessages/SGXRAMessage0.h"
#include "SGXRAMessages/SGXRAMessage1.h"
#include "SGXRAMessages/SGXRAMessage2.h"
#include "SGXRAMessages/SGXRAMessage3.h"
#include "SGXRAMessages/SGXRAMessage4.h"
#include "SGXRAMessages/SGXRAMessageErr.h"

#include "Networking/Connection.h"
#include "../common/CryptoTools.h"
#include "../common/sgx_ra_msg4.h"

namespace
{
	std::vector<uint32_t> g_acceptedExGID =
	{
		0,
	};
}

namespace 
{
	std::map<std::string, SGXRAMessage::Type> g_msgTypeNameMap = 
	{
		std::pair<std::string, SGXRAMessage::Type>("MSG0_SEND", SGXRAMessage::Type::MSG0_SEND),
		std::pair<std::string, SGXRAMessage::Type>("MSG0_RESP", SGXRAMessage::Type::MSG0_RESP),
		std::pair<std::string, SGXRAMessage::Type>("MSG1_SEND", SGXRAMessage::Type::MSG1_SEND),
		//std::pair<std::string, SGXRAMessage::Type>("MSG1_RESP", SGXRAMessage::Type::MSG1_RESP),
		//std::pair<std::string, SGXRAMessage::Type>("MSG2_SEND", SGXRAMessage::Type::MSG2_SEND),
		std::pair<std::string, SGXRAMessage::Type>("MSG2_RESP", SGXRAMessage::Type::MSG2_RESP),
		std::pair<std::string, SGXRAMessage::Type>("MSG3_SEND", SGXRAMessage::Type::MSG3_SEND),
		//std::pair<std::string, SGXRAMessage::Type>("MSG3_RESP", SGXRAMessage::Type::MSG3_RESP),
		//std::pair<std::string, SGXRAMessage::Type>("MSG4_SEND", SGXRAMessage::Type::MSG4_SEND),
		std::pair<std::string, SGXRAMessage::Type>("MSG4_RESP", SGXRAMessage::Type::MSG4_RESP),
		std::pair<std::string, SGXRAMessage::Type>("ERRO_RESP", SGXRAMessage::Type::ERRO_RESP),
		std::pair<std::string, SGXRAMessage::Type>("OTHER", SGXRAMessage::Type::OTHER),
	};
}

SGXRemoteAttestationSession::~SGXRemoteAttestationSession()
{
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

	auto it = g_msgTypeNameMap.find(jsonRoot["MsgSubType"].asString());
	if (it == g_msgTypeNameMap.end() || it->second == SGXRAMessage::Type::OTHER)
	{
		LOGI("Recv INVALID MESSAGE!");
		return nullptr;
	}

	switch (it->second)
	{
	case SGXRAMessage::Type::MSG0_SEND:
		return new SGXRAMessage0Send(jsonRoot);
	case SGXRAMessage::Type::MSG0_RESP:
		return new SGXRAMessage0Resp(jsonRoot);
	case SGXRAMessage::Type::MSG1_SEND:
		return new SGXRAMessage1(jsonRoot);
	case SGXRAMessage::Type::MSG2_RESP:
		return new SGXRAMessage2(jsonRoot);
	case SGXRAMessage::Type::MSG3_SEND:
		return new SGXRAMessage3(jsonRoot);
	case SGXRAMessage::Type::MSG4_RESP:
		return new SGXRAMessage4(jsonRoot);
	case SGXRAMessage::Type::ERRO_RESP:
		return new SGXRAMessageErr(jsonRoot);
	default:
		return nullptr;
	}
}

bool SGXRemoteAttestationSession::ProcessClientSideRA(EnclaveBase & enclave)
{
	if (!m_connection)
	{
		return false;
	}

	SGXEnclave* sgxEnclave = dynamic_cast<SGXEnclave*>(&enclave);
	if (!sgxEnclave)
	{
		return false;
	}
	sgx_status_t enclaveRes = SGX_SUCCESS;
	enclaveRes = sgxEnclave->InitRAEnvironment();
	if (enclaveRes != SGX_SUCCESS)
	{
		return false;
	}
	
	RAMessages* resp = nullptr;
	std::string msgBuffer;
	std::string msgSenderID = sgxEnclave->GetRASenderID();

	SGXRAMessage0Send msg0s(msgSenderID, sgxEnclave->GetExGroupID());
	m_connection->Send(msg0s.ToJsonString());
	m_connection->Receive(msgBuffer);
	resp = JsonMessageParser(msgBuffer);
	SGXRAMessage0Resp* msg0r = dynamic_cast<SGXRAMessage0Resp*>(resp);
	if (!resp || !msg0r || !msg0r->IsValid())
	{
		delete resp;
		SGXRAMessageErr errMsg(msgSenderID, "Wrong response message!");
		m_connection->Send(errMsg.ToJsonString());
		return false;
	}

	sgx_ec256_public_t spRAPubKey;
	DeserializePubKey(msg0r->GetRAPubKey(), spRAPubKey);

	sgx_ra_context_t raContextID = 0;
	sgx_ra_msg1_t msg1Data;

	enclaveRes = sgxEnclave->ProcessRAMsg0Resp(msg0r->GetSenderID(), spRAPubKey, false, raContextID, msg1Data);
	if (enclaveRes != SGX_SUCCESS)
	{
		delete resp;
		SGXRAMessageErr errMsg(msgSenderID, "Enclave process error!");
		m_connection->Send(errMsg.ToJsonString());
		return false;
	}

	//Clean Message 0 response.
	delete resp;
	resp = nullptr;
	msg0r = nullptr;

	SGXRAMessage1 msg1(msgSenderID, msg1Data);

	m_connection->Send(msg1.ToJsonString());
	m_connection->Receive(msgBuffer);
	resp = JsonMessageParser(msgBuffer);
	SGXRAMessage2* msg2 = dynamic_cast<SGXRAMessage2*>(resp);
	if (!resp || !msg2 || !msg2->IsValid())
	{
		delete resp;
		SGXRAMessageErr errMsg(msgSenderID, "Wrong response message!");
		m_connection->Send(errMsg.ToJsonString());
		return false;
	}

	sgx_ra_msg3_t msg3Data;
	std::vector<uint8_t> quote;
	enclaveRes = sgxEnclave->ProcessRAMsg2(msg2->GetSenderID(), msg2->GetMsg2Data(), sizeof(sgx_ra_msg2_t) + msg2->GetMsg2Data().sig_rl_size, msg3Data, quote, raContextID);
	if (enclaveRes != SGX_SUCCESS)
	{
		delete resp;
		SGXRAMessageErr errMsg(msgSenderID, "Enclave process error!");
		m_connection->Send(errMsg.ToJsonString());
		return false;
	}

	//Clean Message 2 (Message 1 response).
	delete resp;
	resp = nullptr;
	msg2 = nullptr;

	SGXRAMessage3 msg3(msgSenderID, msg3Data, quote);

	m_connection->Send(msg3.ToJsonString());
	m_connection->Receive(msgBuffer);
	resp = JsonMessageParser(msgBuffer);
	SGXRAMessage4* msg4 = dynamic_cast<SGXRAMessage4*>(resp);
	if (!resp || !msg4 || !msg4->IsValid())
	{
		delete resp;
		SGXRAMessageErr errMsg(msgSenderID, "Wrong response message!");
		m_connection->Send(errMsg.ToJsonString());
		return false;
	}
	enclaveRes = sgxEnclave->ProcessRAMsg4(msg4->GetSenderID(), msg4->GetMsg4Data(), msg4->GetMsg4Signature());
	if (enclaveRes != SGX_SUCCESS)
	{
		delete resp;
		return false;
	}

	//Clean Message 4 (Message 3 response).
	delete resp;
	resp = nullptr;
	msg4 = nullptr;

	return true;
}

bool SGXRemoteAttestationSession::ProcessServerSideRA(EnclaveBase & enclave)
{
	if (!m_connection)
	{
		return false;
	}

	SGXEnclave* sgxEnclave = dynamic_cast<SGXEnclave*>(&enclave);
	if (!sgxEnclave)
	{
		return false;
	}
	sgx_status_t enclaveRes = SGX_SUCCESS;
	enclaveRes = sgxEnclave->InitRAEnvironment();
	if (enclaveRes != SGX_SUCCESS)
	{
		return false;
	}

	RAMessages* reqs = nullptr;
	SGXRAMessage* resp = nullptr;
	std::string msgBuffer;
	std::string msgSenderID = sgxEnclave->GetRASenderID();

	m_connection->Receive(msgBuffer);
	reqs = JsonMessageParser(msgBuffer);

	SGXRAMessage0Send* msg0s = dynamic_cast<SGXRAMessage0Send*>(reqs);
	if (!reqs || !msg0s || !msg0s->IsValid())
	{
		delete reqs;
		SGXRAMessageErr errMsg(msgSenderID, "Wrong request message!");
		m_connection->Send(errMsg.ToJsonString());
		return false;
	}

	if (std::find(g_acceptedExGID.begin(), g_acceptedExGID.end(), msg0s->GetExtendedGroupID()) != g_acceptedExGID.end())
	{
		enclaveRes = sgxEnclave->ProcessRAMsg0Send(msg0s->GetSenderID());
		if (enclaveRes != SGX_SUCCESS)
		{
			delete reqs;
			SGXRAMessageErr errMsg(msgSenderID, "Enclave process error!");
			m_connection->Send(errMsg.ToJsonString());
			return false;
		}
		else
		{
			resp = new SGXRAMessage0Resp(msgSenderID, msgSenderID);
		}
	}
	else
	{
		delete reqs;
		SGXRAMessageErr errMsg(msgSenderID, "Extended Group ID is not accepted!");
		m_connection->Send(errMsg.ToJsonString());
		return false;
	}

	m_connection->Send(resp->ToJsonString());
	delete resp;
	resp = nullptr;
	delete reqs;
	reqs = nullptr;
	msg0s = nullptr;

	m_connection->Receive(msgBuffer);
	reqs = JsonMessageParser(msgBuffer);

	SGXRAMessage1* msg1 = dynamic_cast<SGXRAMessage1*>(reqs);
	if (!reqs || !msg1 || !msg1->IsValid())
	{
		delete reqs;
		SGXRAMessageErr errMsg(msgSenderID, "Wrong request message!");
		m_connection->Send(errMsg.ToJsonString());
		return false;
	}

	sgx_ra_msg2_t msg2Data;
	enclaveRes = sgxEnclave->ProcessRAMsg1(msg1->GetSenderID(), msg1->GetMsg1Data(), msg2Data);
	if (enclaveRes != SGX_SUCCESS)
	{
		delete reqs;
		SGXRAMessageErr errMsg(msgSenderID, "Extended Group ID is not accepted!");
		m_connection->Send(errMsg.ToJsonString());
		return false;
	}
	resp = new SGXRAMessage2(msgSenderID, msg2Data, msg1->GetMsg1Data().gid);

	m_connection->Send(resp->ToJsonString());
	delete resp;
	resp = nullptr;
	delete reqs;
	reqs = nullptr;
	msg1 = nullptr;

	m_connection->Receive(msgBuffer);
	reqs = JsonMessageParser(msgBuffer);

	SGXRAMessage3* msg3 = dynamic_cast<SGXRAMessage3*>(reqs);
	if (!reqs || !msg3 || !msg3->IsValid())
	{
		delete reqs;
		SGXRAMessageErr errMsg(msgSenderID, "Wrong request message!");
		m_connection->Send(errMsg.ToJsonString());
		return false;
	}

	sgx_ra_msg4_t msg4Data;
	sgx_ec256_signature_t msg4Sign;

	enclaveRes = sgxEnclave->ProcessRAMsg3(msg3->GetSenderID(), msg3->GetMsg3Data(), msg3->GetMsg3DataSize(), "", "", msg4Data, msg4Sign);
	if (enclaveRes != SGX_SUCCESS)
	{
		delete reqs;
		SGXRAMessageErr errMsg(msgSenderID, "Enclave process error!");
		m_connection->Send(errMsg.ToJsonString());
		return false;
	}
	resp = new SGXRAMessage4(msgSenderID, msg4Data, msg4Sign);

	m_connection->Send(resp->ToJsonString());
	delete resp;
	resp = nullptr;
	delete reqs;
	reqs = nullptr;
	msg3 = nullptr;

	return true;
}