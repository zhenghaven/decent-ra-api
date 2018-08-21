#include "DecentralizedMessage.h"

#include <json/json.h>

#include "MessageException.h"

std::string DecentralizedMessage::ParseType(const Json::Value & MsgRootContent)
{
	if (MsgRootContent.isMember(DecentralizedMessage::LABEL_ROOT) && MsgRootContent[DecentralizedMessage::LABEL_ROOT].isObject() &&
		MsgRootContent[DecentralizedMessage::LABEL_ROOT].isMember(LABEL_TYPE) && MsgRootContent[DecentralizedMessage::LABEL_ROOT][LABEL_TYPE].isString()
		)
	{
		return MsgRootContent[DecentralizedMessage::LABEL_ROOT][LABEL_TYPE].asString();
	}
	throw MessageParseException();
}

DecentralizedMessage::DecentralizedMessage(const std::string & senderID) :
	Messages(senderID)
{
}

DecentralizedMessage::DecentralizedMessage(const Json::Value & msg) :
	Messages(msg)
{
	ParseType(msg[Messages::LABEL_ROOT]);
}

DecentralizedMessage::~DecentralizedMessage()
{
}

std::string DecentralizedMessage::GetMessageCategoryStr() const
{
	return DecentralizedMessage::VALUE_CAT;
}

Json::Value & DecentralizedMessage::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = Messages::GetJsonMsg(outJson);

	parent[DecentralizedMessage::LABEL_ROOT] = Json::objectValue;
	parent[DecentralizedMessage::LABEL_ROOT][DecentralizedMessage::LABEL_TYPE] = GetMessageTypeStr();

	return parent[DecentralizedMessage::LABEL_ROOT];
}

std::string DecentralizedErrMsg::ParseErrorMsg(const Json::Value & DecentralizedRoot)
{
	if (DecentralizedRoot.isMember(DecentralizedErrMsg::LABEL_ERR_MSG) && DecentralizedRoot[DecentralizedErrMsg::LABEL_ERR_MSG].isString())
	{
		return DecentralizedRoot[DecentralizedErrMsg::LABEL_ERR_MSG].asString();
	}
	throw MessageParseException();
}

DecentralizedErrMsg::DecentralizedErrMsg(const std::string & senderID, const std::string & errStr) :
	DecentralizedMessage(senderID),
	m_errStr(errStr)
{
}

DecentralizedErrMsg::DecentralizedErrMsg(const Json::Value & msg) :
	DecentralizedMessage(msg),
	m_errStr(ParseErrorMsg(msg[Messages::LABEL_ROOT][DecentralizedMessage::LABEL_ROOT]))
{
}

DecentralizedErrMsg::~DecentralizedErrMsg()
{
}

std::string DecentralizedErrMsg::GetMessageTypeStr() const
{
	return VALUE_TYPE;
}

const std::string & DecentralizedErrMsg::GetErrStr() const
{
	return m_errStr;
}

Json::Value & DecentralizedErrMsg::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = DecentralizedMessage::GetJsonMsg(outJson);

	//parent[SGXRASPMessage::LABEL_TYPE] = VALUE_TYPE;
	parent[LABEL_ERR_MSG] = m_errStr;

	return parent;
}

DecentralizedRAHandshake::DecentralizedRAHandshake(const std::string & senderID) :
	DecentralizedMessage(senderID)
{
}

DecentralizedRAHandshake::DecentralizedRAHandshake(const Json::Value & msg) :
	DecentralizedMessage(msg)
{
}

DecentralizedRAHandshake::~DecentralizedRAHandshake()
{
}

std::string DecentralizedRAHandshake::GetMessageTypeStr() const
{
	return VALUE_TYPE;
}

Json::Value & DecentralizedRAHandshake::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = DecentralizedMessage::GetJsonMsg(outJson);

	//parent[SGXRASPMessage::LABEL_TYPE] = VALUE_TYPE;

	return parent;
}

DecentralizedRAHandshakeAck::DecentralizedRAHandshakeAck(const std::string & senderID) :
	DecentralizedMessage(senderID)
{
}

DecentralizedRAHandshakeAck::DecentralizedRAHandshakeAck(const Json::Value & msg) :
	DecentralizedMessage(msg)
{
}

DecentralizedRAHandshakeAck::~DecentralizedRAHandshakeAck()
{
}

std::string DecentralizedRAHandshakeAck::GetMessageTypeStr() const
{
	return VALUE_TYPE;
}

Json::Value & DecentralizedRAHandshakeAck::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = DecentralizedMessage::GetJsonMsg(outJson);

	//parent[SGXRASPMessage::LABEL_TYPE] = VALUE_TYPE;

	return parent;
}

DecentralizedReverseReq::DecentralizedReverseReq(const std::string & senderID) :
	DecentralizedMessage(senderID)
{
}

DecentralizedReverseReq::DecentralizedReverseReq(const Json::Value & msg) :
	DecentralizedMessage(msg)
{
}

DecentralizedReverseReq::~DecentralizedReverseReq()
{
}

std::string DecentralizedReverseReq::GetMessageTypeStr() const
{
	return VALUE_TYPE;
}

Json::Value & DecentralizedReverseReq::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = DecentralizedMessage::GetJsonMsg(outJson);

	//parent[SGXRASPMessage::LABEL_TYPE] = VALUE_TYPE;

	return parent;
}
