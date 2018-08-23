#include "DecentMessage.h"

#include <json/json.h>

#include "../MessageException.h"

std::string DecentMessage::ParseType(const Json::Value & MsgRootContent)
{
	if (MsgRootContent.isMember(LABEL_ROOT) && MsgRootContent[LABEL_ROOT].isObject() &&
		MsgRootContent[LABEL_ROOT].isMember(LABEL_TYPE) && MsgRootContent[LABEL_ROOT][LABEL_TYPE].isString()
		)
	{
		return MsgRootContent[LABEL_ROOT][LABEL_TYPE].asString();
	}
	throw MessageParseException();
}

DecentMessage::DecentMessage(const std::string & senderID) :
	Messages(senderID)
{
}

DecentMessage::DecentMessage(const Json::Value & msg) :
	Messages(msg)
{
	ParseType(msg[Messages::LABEL_ROOT]);
}

DecentMessage::~DecentMessage()
{
}

std::string DecentMessage::GetMessageCategoryStr() const
{
	return VALUE_CAT;
}

Json::Value & DecentMessage::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = Messages::GetJsonMsg(outJson);

	parent[LABEL_ROOT] = Json::objectValue;
	parent[LABEL_ROOT][LABEL_TYPE] = GetMessageTypeStr();

	return parent[LABEL_ROOT];
}

std::string DecentErrMsg::ParseErrorMsg(const Json::Value & DecentRoot)
{
	if (DecentRoot.isMember(LABEL_ERR_MSG) && DecentRoot[LABEL_ERR_MSG].isString())
	{
		return DecentRoot[LABEL_ERR_MSG].asString();
	}
	throw MessageParseException();
}

DecentErrMsg::DecentErrMsg(const std::string & senderID, const std::string & errStr) :
	DecentMessage(senderID),
	m_errStr(errStr)
{
}

DecentErrMsg::DecentErrMsg(const Json::Value & msg) :
	DecentMessage(msg),
	m_errStr(ParseErrorMsg(msg[Messages::LABEL_ROOT][DecentMessage::LABEL_ROOT]))
{
}

DecentErrMsg::~DecentErrMsg()
{
}

std::string DecentErrMsg::GetMessageTypeStr() const
{
	return VALUE_TYPE;
}

const std::string & DecentErrMsg::GetErrStr() const
{
	return m_errStr;
}

Json::Value & DecentErrMsg::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = DecentMessage::GetJsonMsg(outJson);

	//parent[DecentMessage::LABEL_TYPE] = VALUE_TYPE;
	parent[LABEL_ERR_MSG] = m_errStr;

	return parent;
}

DecentRAHandshake::DecentRAHandshake(const std::string & senderID) :
	DecentMessage(senderID)
{
}

DecentRAHandshake::DecentRAHandshake(const Json::Value & msg) :
	DecentMessage(msg)
{
}

DecentRAHandshake::~DecentRAHandshake()
{
}

std::string DecentRAHandshake::GetMessageTypeStr() const
{
	return VALUE_TYPE;
}

Json::Value & DecentRAHandshake::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = DecentMessage::GetJsonMsg(outJson);

	//parent[DecentMessage::LABEL_TYPE] = VALUE_TYPE;

	return parent;
}

std::string DecentRAHandshakeAck::ParseSelfRAReport(const Json::Value & DecentRoot)
{
	if (DecentRoot.isMember(LABEL_SELF_REPORT) && DecentRoot[LABEL_SELF_REPORT].isString())
	{
		return DecentRoot[LABEL_SELF_REPORT].asString();
	}
	throw MessageParseException();
}

DecentRAHandshakeAck::DecentRAHandshakeAck(const std::string & senderID, const std::string& selfRAReport) :
	DecentMessage(senderID),
	m_selfRAReport(selfRAReport)
{
}

DecentRAHandshakeAck::DecentRAHandshakeAck(const Json::Value & msg) :
	DecentMessage(msg),
	m_selfRAReport(ParseSelfRAReport(msg[Messages::LABEL_ROOT][DecentMessage::LABEL_ROOT]))
{
}

DecentRAHandshakeAck::~DecentRAHandshakeAck()
{
}

std::string DecentRAHandshakeAck::GetMessageTypeStr() const
{
	return VALUE_TYPE;
}

const std::string & DecentRAHandshakeAck::GetSelfRAReport() const
{
	return m_selfRAReport;
}

Json::Value & DecentRAHandshakeAck::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = DecentMessage::GetJsonMsg(outJson);

	//parent[DecentMessage::LABEL_TYPE] = VALUE_TYPE;
	parent[LABEL_SELF_REPORT] = m_selfRAReport;

	return parent;
}
