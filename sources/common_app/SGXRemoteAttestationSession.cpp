#include "SGXRemoteAttestationSession.h"

#include <cstring>
#include <map>

#include <json/json.h>

#include "Common.h"
#include "SGXRAMessages/SGXRAMessage.h"
#include "SGXRAMessages/SGXRAMessage0.h"
#include "SGXRAMessages/SGXRAMessage1.h"
#include "SGXRAMessages/SGXRAMessage2.h"
#include "SGXRAMessages/SGXRAMessage3.h"
#include "SGXRAMessages/SGXRAMessageErr.h"

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

RAMessages * SGXRemoteAttestationSession::SendMessages(const std::string& senderID, const RAMessages & msg)
{
	const SGXRAMessage* sgxMsg = dynamic_cast<const SGXRAMessage*>(&msg);
	if (!sgxMsg || sgxMsg->IsResp())
	{
		SendErrorMessages(SGXRAMessageErr(senderID, "Server Error!"));
		return nullptr;
	}

	std::string tmp = sgxMsg->ToJsonString();
	m_socket.send(boost::asio::buffer(tmp.data(), tmp.size() + 1));
	LOGI("Sent Msg: %s\n", tmp.c_str());
	size_t actualSize = m_socket.receive(boost::asio::buffer(&m_buffer[0], m_buffer.size()));
	m_buffer[actualSize] = '\0';
	LOGI("Recv Msg: %s\n", m_buffer.c_str());
	
	Json::Value jsonRoot;
	Json::CharReaderBuilder rbuilder;
	rbuilder["collectComments"] = false;
	std::string errStr;

	const std::unique_ptr<Json::CharReader> reader(rbuilder.newCharReader());
	bool isValid = reader->parse(m_buffer.c_str(), m_buffer.c_str() + actualSize, &jsonRoot, &errStr);

	if (!isValid
		|| !jsonRoot.isMember("MsgSubType")
		|| !jsonRoot["MsgSubType"].isString())
	{
		LOGI("Recv INVALID MESSAGE!");
		SendErrorMessages(SGXRAMessageErr(senderID, "Wrong response message!"));
		return nullptr;
	}

	auto it = g_msgTypeNameMap.find(jsonRoot["MsgSubType"].asString());
	if (it == g_msgTypeNameMap.end() || it->second == SGXRAMessage::Type::OTHER)
	{
		LOGI("Recv INVALID MESSAGE!");
		SendErrorMessages(SGXRAMessageErr(senderID, "Wrong response message!"));
		return nullptr;
	}

	if (it->second == SGXRAMessage::Type::ERRO_RESP)
	{
		return nullptr;
	}

	switch (sgxMsg->GetType())
	{
	case SGXRAMessage::Type::MSG0_SEND:
		return new SGXRAMessage0Resp(jsonRoot);
	case SGXRAMessage::Type::MSG1_SEND:
		return new SGXRAMessage2(jsonRoot);
	case SGXRAMessage::Type::MSG3_SEND:
		return nullptr;//new SGXRAMessage4(jsonRoot);
	default:
		return nullptr;
	}
}

void SGXRemoteAttestationSession::SendErrorMessages(const RAMessages & msg)
{
	std::string tmp = dynamic_cast<const SGXRAMessageErr&>(msg).ToJsonString();
	m_socket.send(boost::asio::buffer(tmp.data(), tmp.size() + 1));
	LOGI("Sent Msg: %s\n", tmp.c_str());
}

bool SGXRemoteAttestationSession::RecvMessages(const std::string& senderID, MsgProcessor msgProcessor)
{
	size_t actualSize = m_socket.receive(boost::asio::buffer(&m_buffer[0], m_buffer.size()));
	m_buffer[actualSize] = '\0';
	LOGI("Recv Msg: %s\n", m_buffer.c_str());

	Json::Value jsonRoot;
	Json::CharReaderBuilder rbuilder;
	rbuilder["collectComments"] = false;
	std::string errStr;

	const std::unique_ptr<Json::CharReader> reader(rbuilder.newCharReader());
	bool isValid = reader->parse(m_buffer.c_str(), m_buffer.c_str() + actualSize, &jsonRoot, &errStr);

	if (!isValid
		|| !jsonRoot.isMember("MsgSubType")
		|| !jsonRoot["MsgSubType"].isString())
	{
		LOGI("Recv INVALID MESSAGE!");
		SendErrorMessages(SGXRAMessageErr(senderID, "Wrong response message!"));
		return false;
	}

	auto it = g_msgTypeNameMap.find(jsonRoot["MsgSubType"].asString());
	if (it == g_msgTypeNameMap.end() || it->second == SGXRAMessage::Type::OTHER)
	{
		LOGI("Recv INVALID MESSAGE!");
		SendErrorMessages(SGXRAMessageErr(senderID, "Wrong response message!"));
		return false;
	}

	SGXRAMessage* sgxResp = nullptr; 
	RAMessages* resp = nullptr;
	switch (it->second)
	{
	case SGXRAMessage::Type::MSG0_SEND:
	{
		SGXRAMessage0Send msg0s(jsonRoot);
		resp = msgProcessor(msg0s);
		sgxResp = dynamic_cast<SGXRAMessage*>(resp);
		break;
	}
	case SGXRAMessage::Type::MSG1_SEND:
	{
		SGXRAMessage1 msg1(jsonRoot);
		resp = msgProcessor(msg1);
		sgxResp = dynamic_cast<SGXRAMessage*>(resp);
		break;
	}
	case SGXRAMessage::Type::MSG3_SEND:
	{
		SGXRAMessage3 msg3(jsonRoot);
		resp = msgProcessor(msg3);
		sgxResp = dynamic_cast<SGXRAMessage*>(resp);
		break;
	}
	case SGXRAMessage::Type::ERRO_RESP:
	{
		return false;
	}
	default:
		break;
	}
	if (!sgxResp)
	{
		SendErrorMessages(SGXRAMessageErr(senderID, "Server Error!"));
		delete resp;
		return false;
	}

	std::string tmp = sgxResp->ToJsonString();
	m_socket.send(boost::asio::buffer(tmp.data(), tmp.size() + 1));
	LOGI("Sent Msg: %s\n", tmp.c_str());
	if (sgxResp->GetType() == SGXRAMessage::Type::ERRO_RESP)
	{
		delete sgxResp;
		return false;
	}
	delete sgxResp;
	return true;
}

//RAMessages* SGXRemoteAttestationSession::ProcessMessages()
//{
//	switch (RemoteAttestationSession::GetMode())
//	{
//	case RemoteAttestationSession::Mode::Client:
//		return ProcessClientMessages();
//	case RemoteAttestationSession::Mode::Server:
//		return ProcessServerMessages();
//	default:
//		return false;
//	}
//}
//
//RAMessages* SGXRemoteAttestationSession::ProcessServerMessages()
//{
//	m_socket.receive(boost::asio::buffer(&m_buffer[0], m_buffer.size()));
//	LOGI("%s\n", m_buffer.c_str());
//	m_socket.send(boost::asio::buffer(&m_buffer[0], std::strlen(m_buffer.c_str())));
//	return true;
//}
//
//RAMessages* SGXRemoteAttestationSession::ProcessClientMessages()
//{
//	std::string msg = "TEST MESSAGE";
//	memcpy(&m_buffer[0], &msg[0], msg.size());
//	m_socket.send(boost::asio::buffer(&m_buffer[0], std::strlen(m_buffer.c_str())));
//	m_socket.receive(boost::asio::buffer(&m_buffer[0], m_buffer.size()));
//	LOGI("%s\n", m_buffer.c_str());
//	LOGI("buffer size: %d\n", m_buffer.size());
//	return true;
//}
