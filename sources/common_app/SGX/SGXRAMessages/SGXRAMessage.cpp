#include "SGXRAMessage.h"

#include <json/json.h>

#include "../../MessageException.h"

SGXRAClientMessage::SGXRAClientMessage(const std::string & senderID) :
	Messages(senderID)
{
}

SGXRAClientMessage::SGXRAClientMessage(const Json::Value & msg) :
	Messages(msg)
{
	if (!(msg[Messages::LABEL_ROOT].isMember(SGXRAClientMessage::LABEL_ROOT) &&
		msg[Messages::LABEL_ROOT][SGXRAClientMessage::LABEL_ROOT].isObject()))
	{
		throw MessageParseException();
	}
}

SGXRAClientMessage::~SGXRAClientMessage()
{
}

std::string SGXRAClientMessage::GetMessageCategoryStr() const
{
	return SGXRAClientMessage::VALUE_CAT;
}

Json::Value & SGXRAClientMessage::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = Messages::GetJsonMsg(outJson);

	parent[SGXRAClientMessage::LABEL_ROOT] = Json::objectValue;

	return parent[SGXRAClientMessage::LABEL_ROOT];
}

SGXRASPMessage::SGXRASPMessage(const std::string & senderID) :
	Messages(senderID)
{
}

SGXRASPMessage::SGXRASPMessage(const Json::Value & msg) :
	Messages(msg)
{
	if (!(msg[Messages::LABEL_ROOT].isMember(SGXRAClientMessage::LABEL_ROOT) &&
		msg[Messages::LABEL_ROOT][SGXRASPMessage::LABEL_ROOT].isObject()))
	{
		throw MessageParseException();
	}
}

SGXRASPMessage::~SGXRASPMessage()
{
}

std::string SGXRASPMessage::GetMessageCategoryStr() const
{
	return SGXRASPMessage::VALUE_CAT;
}

Json::Value & SGXRASPMessage::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = Messages::GetJsonMsg(outJson);

	parent[SGXRASPMessage::LABEL_ROOT] = Json::objectValue;

	return parent[SGXRASPMessage::LABEL_ROOT];
}

std::string SGXRAClientErrMsg::ParseErrorMsg(const Json::Value & SGXRAClientRoot)
{
	if (SGXRAClientRoot.isMember(SGXRAClientErrMsg::LABEL_ERR_MSG) && SGXRAClientRoot[SGXRAClientErrMsg::LABEL_ERR_MSG].isString())
	{
		return SGXRAClientRoot[SGXRAClientErrMsg::LABEL_ERR_MSG].asString();
	}
	throw MessageParseException();
}

SGXRAClientErrMsg::SGXRAClientErrMsg(const std::string & senderID, const std::string & errStr) :
	SGXRAClientMessage(senderID),
	m_errStr(errStr)
{
}

SGXRAClientErrMsg::SGXRAClientErrMsg(const Json::Value & msg) :
	SGXRAClientMessage(msg),
	m_errStr(ParseErrorMsg(msg[Messages::LABEL_ROOT][SGXRAClientMessage::LABEL_ROOT]))
{
}

SGXRAClientErrMsg::~SGXRAClientErrMsg()
{
}

std::string SGXRAClientErrMsg::GetMessageTypeStr() const
{
	return VALUE_TYPE;
}

const std::string & SGXRAClientErrMsg::GetErrStr() const
{
	return m_errStr;
}

Json::Value & SGXRAClientErrMsg::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = SGXRAClientMessage::GetJsonMsg(outJson);

	parent[SGXRAClientMessage::LABEL_TYPE] = VALUE_TYPE;
	parent[LABEL_ERR_MSG] = m_errStr;

	return parent;
}

std::string SGXRASPErrMsg::ParseErrorMsg(const Json::Value & SGXRASPRoot)
{
	if (SGXRASPRoot.isMember(SGXRASPErrMsg::LABEL_ERR_MSG) && SGXRASPRoot[SGXRASPErrMsg::LABEL_ERR_MSG].isString())
	{
		return SGXRASPRoot[SGXRASPErrMsg::LABEL_ERR_MSG].asString();
	}
	throw MessageParseException();
}

SGXRASPErrMsg::SGXRASPErrMsg(const std::string & senderID, const std::string & errStr) :
	SGXRASPMessage(senderID),
	m_errStr(errStr)
{
}

SGXRASPErrMsg::SGXRASPErrMsg(const Json::Value & msg) :
	SGXRASPMessage(msg),
	m_errStr(ParseErrorMsg(msg[Messages::LABEL_ROOT][SGXRASPMessage::LABEL_ROOT]))
{
}

SGXRASPErrMsg::~SGXRASPErrMsg()
{
}

std::string SGXRASPErrMsg::GetMessageTypeStr() const
{
	return VALUE_TYPE;
}

const std::string & SGXRASPErrMsg::GetErrStr() const
{
	m_errStr;
}

Json::Value & SGXRASPErrMsg::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = SGXRASPMessage::GetJsonMsg(outJson);

	parent[SGXRASPMessage::LABEL_TYPE] = VALUE_TYPE;
	parent[LABEL_ERR_MSG] = m_errStr;

	return parent;
}
