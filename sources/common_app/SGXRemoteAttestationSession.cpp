#include "SGXRemoteAttestationSession.h"

#include <cstring>
#include <map>

#include <json/json.h>

#include "Common.h"
#include "SGXRAMessages/SGXRAMessage.h"
#include "SGXRAMessages/SGXRAMessage0.h"

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
		std::pair<std::string, SGXRAMessage::Type>("OTHER", SGXRAMessage::Type::OTHER),
	};
}

SGXRemoteAttestationSession::~SGXRemoteAttestationSession()
{
}

RAMessages * SGXRemoteAttestationSession::SendMessages(const RAMessages & msg)
{
	const SGXRAMessage* sgxMsg = dynamic_cast<const SGXRAMessage*>(&msg);
	if (!sgxMsg || sgxMsg->IsResp())
	{
		return nullptr;
	}

	std::string tmp = sgxMsg->ToJsonString();
	memcpy(&m_buffer[0], &tmp[0], tmp.size());
	m_socket.send(boost::asio::buffer(&m_buffer[0], std::strlen(m_buffer.c_str())));
	m_socket.receive(boost::asio::buffer(&m_buffer[0], m_buffer.size()));
	size_t actualSize = std::strlen(m_buffer.c_str());
	LOGI("Recv Msg: %s\n", m_buffer.c_str());
	
	Json::Value jsonRoot;
	Json::CharReaderBuilder rbuilder;
	rbuilder["collectComments"] = false;
	std::string errStr;

	const std::unique_ptr<Json::CharReader> reader(rbuilder.newCharReader());
	bool isValid = reader->parse(m_buffer.c_str(), m_buffer.c_str() + actualSize, &jsonRoot, &errStr);

	if (!isValid
		|| !jsonRoot.isMember("MsgType"))
	{
		LOGI("Recv INVALID MESSAGE!");
		return nullptr;
	}

	switch (sgxMsg->GetType())
	{
	case SGXRAMessage::Type::MSG0_SEND:
		return new SGXRAMessage0Resp(jsonRoot);
	default:
		return nullptr;
	}
}

bool SGXRemoteAttestationSession::RecvMessages(MsgProcessor msgProcessor)
{
	m_socket.receive(boost::asio::buffer(&m_buffer[0], m_buffer.size()));
	size_t actualSize = std::strlen(m_buffer.c_str());
	LOGI("Recv Msg: %s\n", m_buffer.c_str());

	Json::Value jsonRoot;
	Json::CharReaderBuilder rbuilder;
	rbuilder["collectComments"] = false;
	std::string errStr;

	const std::unique_ptr<Json::CharReader> reader(rbuilder.newCharReader());
	bool isValid = reader->parse(m_buffer.c_str(), m_buffer.c_str() + actualSize, &jsonRoot, &errStr);

	if (!isValid
		|| !jsonRoot.isMember("MsgType"))
	{
		LOGI("Recv INVALID MESSAGE!");
		return false;
	}

	auto it = g_msgTypeNameMap.find(jsonRoot["MsgType"].asString());
	if (it == g_msgTypeNameMap.end() || it->second == SGXRAMessage::Type::OTHER)
	{
		LOGI("Recv INVALID MESSAGE!");
		return false;
	}

	SGXRAMessage* sgxResp = nullptr;
	switch (it->second)
	{
	case SGXRAMessage::Type::MSG0_SEND:
	{
		SGXRAMessage0Send msg0s(jsonRoot);
		RAMessages* resp = msgProcessor(&msg0s);
		sgxResp = dynamic_cast<SGXRAMessage*>(resp);
		break;
	}
	case SGXRAMessage::Type::MSG1_SEND:
	{
		SGXRAMessage0Send msg1(jsonRoot);
		RAMessages* resp = msgProcessor(&msg1);
		sgxResp = dynamic_cast<SGXRAMessage*>(resp);
		break;
	}
	default:
		break;
	}
	if (!sgxResp)
	{
		return false;
	}

	std::string tmp = sgxResp->ToJsonString();
	memcpy(&m_buffer[0], &tmp[0], tmp.size());
	m_socket.send(boost::asio::buffer(&m_buffer[0], std::strlen(m_buffer.c_str())));
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
