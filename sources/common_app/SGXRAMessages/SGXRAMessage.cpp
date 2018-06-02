#include "SGXRAMessage.h"

const std::string SGXRAMessage::sk_MessageClass = "SGX_RA";

SGXRAMessage::SGXRAMessage(const std::string& senderID) :
	RAMessages(senderID)
{
}

SGXRAMessage::SGXRAMessage(Json::Value & msg) :
	RAMessages(msg)
{
	if (IsValid())
	{
		if (msg.isMember("child")
			&& msg["child"].isObject())
		{
			Json::Value& root = msg["child"];
			if (root.isMember("Type")
				&& root["Type"].isString()
				&& root["Type"].asString() == "SGX_RA_Classic")
			{
				m_isValid = true;
			}
			else
			{
				m_isValid = false;
			}
		}
		else
		{
			m_isValid = false;
		}
	}
}

SGXRAMessage::~SGXRAMessage()
{
}

void SGXRAMessage::SerializedMessage(std::vector<uint8_t>& outData) const
{
	std::string msg = ToJsonString();
	outData.resize(msg.size());
	memcpy(&outData[0], msg.data(), msg.size());
}

std::string SGXRAMessage::ToJsonString() const
{
	Json::Value jsonRoot;

	GetJsonMsg(jsonRoot);

	return jsonRoot.toStyledString();
}

std::string SGXRAMessage::GetMessgaeSubTypeStr() const
{
	return sk_MessageClass;
}

std::string SGXRAMessage::GetMessageTypeStr(const SGXRAMessage::Type t)
{
	switch (t)
	{
	case SGXRAMessage::Type::MSG0_SEND:
		return "MSG0_SEND";
	case SGXRAMessage::Type::MSG0_RESP:
		return "MSG0_RESP";
	case SGXRAMessage::Type::MSG1_SEND:
		return "MSG1_SEND";
	//case SGXRAMessage::Type::MSG1_RESP:
	//	return "MSG1_RESP";
	//case SGXRAMessage::Type::MSG2_SEND:
	//	return "MSG2_SEND";
	case SGXRAMessage::Type::MSG2_RESP:
		return "MSG2_RESP";
	case SGXRAMessage::Type::MSG3_SEND:
		return "MSG3_SEND";
	//case SGXRAMessage::Type::MSG3_RESP:
	//	return "MSG3_RESP";
	//case SGXRAMessage::Type::MSG4_SEND:
	//	return "MSG4_SEND";
	case SGXRAMessage::Type::MSG4_RESP:
		return "MSG4_RESP";
	default:
		return "OTHER";
	}
}

Json::Value& SGXRAMessage::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = RAMessages::GetJsonMsg(outJson);
	
	parent["child"] = Json::objectValue;
	Json::Value& child = parent["child"];
	child["Type"] = "SGX_RA_Classic";

	return child;
}
