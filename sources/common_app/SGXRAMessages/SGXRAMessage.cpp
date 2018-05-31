#include "SGXRAMessage.h"

const std::string SGXRAMessage::sk_MessageClass = "SGX_RA";

SGXRAMessage::SGXRAMessage()
{
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

bool SGXRAMessage::IsValid() const
{
	return m_isValid;
}

std::string SGXRAMessage::GetMessgaeClass() const
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
