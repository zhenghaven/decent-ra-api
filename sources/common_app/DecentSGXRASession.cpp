#include "DecentSGXRASession.h"

#include <cstring>
#include <map>

#include <json/json.h>

#include "Common.h"
#include "RAMessageRevRAReq.h"
#include "DecentSGXEnclave.h"

#include "DecentMessages/DecentMessage.h"

#include "Networking/Connection.h"
#include "../common/CryptoTools.h"

namespace 
{
	std::map<std::string, DecentMessage::Type> g_msgTypeNameMap =
	{
		std::pair<std::string, DecentMessage::Type>("DECENT_MSG0", DecentMessage::Type::DECENT_MSG0),
		std::pair<std::string, DecentMessage::Type>("DECENT_KEY_REQ", DecentMessage::Type::DECENT_KEY_REQ),
		std::pair<std::string, DecentMessage::Type>("ROOT_NODE_RESP", DecentMessage::Type::ROOT_NODE_RESP),
		std::pair<std::string, DecentMessage::Type>("APPL_NODE_RESP", DecentMessage::Type::APPL_NODE_RESP),
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
		return nullptr;//new SGXRAMessage0Send(jsonRoot);
	case DecentMessage::Type::DECENT_KEY_REQ:
		return nullptr;//new SGXRAMessage0Resp(jsonRoot);
	case DecentMessage::Type::ROOT_NODE_RESP:
		return nullptr;//new SGXRAMessage1(jsonRoot);
	case DecentMessage::Type::APPL_NODE_RESP:
		return nullptr;// new SGXRAMessage2(jsonRoot);
	default:
		return nullptr;
	}
}

DecentSGXRASession::~DecentSGXRASession()
{
}

bool DecentSGXRASession::SendReverseRARequest(const std::string& senderID)
{
	if (!m_connection)
	{
		return false;
	}

	RAMessageRevRAReq msg(senderID);
	m_connection->Send(msg.ToJsonString());

	return true;
}

bool DecentSGXRASession::RecvReverseRARequest()
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

bool DecentSGXRASession::ProcessClientSideRA(EnclaveBase & enclave)
{

	return true;
}

bool DecentSGXRASession::ProcessServerSideRA(EnclaveBase & enclave)
{

	return true;
}