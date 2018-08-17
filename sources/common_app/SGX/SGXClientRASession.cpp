#include "SGXClientRASession.h"

#include <cstring>
#include <map>

#include <json/json.h>

#include "../Common.h"
#include "SGXEnclave.h"
#include "SGXRAMessages/SGXRAMessage.h"
#include "SGXRAMessages/SGXRAMessage0.h"
#include "SGXRAMessages/SGXRAMessage1.h"
#include "SGXRAMessages/SGXRAMessage2.h"
#include "SGXRAMessages/SGXRAMessage3.h"
#include "SGXRAMessages/SGXRAMessage4.h"
#include "SGXRAMessages/SGXRAMessageErr.h"

#include "../Networking/Connection.h"
#include "../../common/DataCoding.h"
#include "../../common/SGX/sgx_ra_msg4.h"
#include "IAS/IASConnector.h"

namespace
{
	std::map<std::string, SGXRAMessage::Type> g_msgTypeNameMap = 
	{
		std::pair<std::string, SGXRAMessage::Type>("MSG0_SEND", SGXRAMessage::Type::MSG0_SEND),
		std::pair<std::string, SGXRAMessage::Type>("MSG0_RESP", SGXRAMessage::Type::MSG0_RESP),
		std::pair<std::string, SGXRAMessage::Type>("MSG1_SEND", SGXRAMessage::Type::MSG1_SEND),
		std::pair<std::string, SGXRAMessage::Type>("MSG2_RESP", SGXRAMessage::Type::MSG2_RESP),
		std::pair<std::string, SGXRAMessage::Type>("MSG3_SEND", SGXRAMessage::Type::MSG3_SEND),
		std::pair<std::string, SGXRAMessage::Type>("MSG4_RESP", SGXRAMessage::Type::MSG4_RESP),
		std::pair<std::string, SGXRAMessage::Type>("ERRO_RESP", SGXRAMessage::Type::ERRO_RESP),
		std::pair<std::string, SGXRAMessage::Type>("OTHER", SGXRAMessage::Type::OTHER),
	};
}

SGXClientRASession::SGXClientRASession(std::unique_ptr<Connection>& m_connection, SGXEnclave& enclave) :
	ClientRASession(m_connection, enclave),
	m_sgxEnclave(enclave)
{
}

SGXClientRASession::~SGXClientRASession()
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

bool SGXClientRASession::ProcessClientSideRA()
{
	if (!m_connection)
	{
		return false;
	}

	sgx_status_t enclaveRes = SGX_SUCCESS;
	
	RAMessages* resp = nullptr;
	std::string msgBuffer;
	std::string msgSenderID = GetSenderID();

	SGXRAMessage0Send msg0s(msgSenderID, m_sgxEnclave.GetExGroupID());
	m_connection->Send(msg0s.ToJsonString());
	m_connection->Receive(msgBuffer);
	resp = JsonMessageParser(msgBuffer);
	SGXRAMessage0Resp* msg0r = dynamic_cast<SGXRAMessage0Resp*>(resp);
	if (!resp || !msg0r || !msg0r->IsValid())
	{
		SGXRAMessageErr errMsg(msgSenderID, "Wrong response message!");
		m_connection->Send(errMsg.ToJsonString());
		delete resp;
		return false;
	}

	sgx_ec256_public_t spRAPubKey;
	DeserializePubKey(msg0r->GetRAPubKey(), spRAPubKey);

	sgx_ra_context_t raContextID = 0;
	sgx_ra_msg1_t msg1Data;

	enclaveRes = m_sgxEnclave.ProcessRAMsg0Resp(msg0r->GetSenderID(), spRAPubKey, false, raContextID, msg1Data);
	if (enclaveRes != SGX_SUCCESS)
	{
		SGXRAMessageErr errMsg(msgSenderID, "Enclave process error!");
		m_connection->Send(errMsg.ToJsonString());
		delete resp;
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
		SGXRAMessageErr errMsg(msgSenderID, "Wrong response message!");
		m_connection->Send(errMsg.ToJsonString());
		delete resp;
		return false;
	}

	std::vector<uint8_t> msg3Data;
	enclaveRes = m_sgxEnclave.ProcessRAMsg2(msg2->GetSenderID(), msg2->GetMsg2Data(), msg3Data, raContextID);
	if (enclaveRes != SGX_SUCCESS)
	{
		SGXRAMessageErr errMsg(msgSenderID, "Enclave process error!");
		m_connection->Send(errMsg.ToJsonString());
		delete resp;
		return false;
	}

	//Clean Message 2 (Message 1 response).
	delete resp;
	resp = nullptr;
	msg2 = nullptr;

	SGXRAMessage3 msg3(msgSenderID, msg3Data);

	m_connection->Send(msg3.ToJsonString());
	m_connection->Receive(msgBuffer);
	resp = JsonMessageParser(msgBuffer);
	SGXRAMessage4* msg4 = dynamic_cast<SGXRAMessage4*>(resp);
	if (!resp || !msg4 || !msg4->IsValid())
	{
		SGXRAMessageErr errMsg(msgSenderID, "Wrong response message!");
		m_connection->Send(errMsg.ToJsonString());
		delete resp;
		return false;
	}
	enclaveRes = m_sgxEnclave.ProcessRAMsg4(msg4->GetSenderID(), msg4->GetMsg4Data(), msg4->GetMsg4Signature(), raContextID);
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
