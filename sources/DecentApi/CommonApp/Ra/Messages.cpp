#include "Messages.h"

#include <json/json.h>

#include "../Net/MessageException.h"

using namespace Decent::Ra::Message;
using namespace Decent::Net;

constexpr char LoadWhiteList::sk_LabelRoot[];
constexpr char LoadWhiteList::sk_ValueCat[];
constexpr char LoadWhiteList::sk_LabelKey[];
constexpr char LoadWhiteList::sk_LabelWhiteList[];

std::string LoadWhiteList::ParseKey(const Json::Value & DecentRoot)
{
	if (DecentRoot.isMember(sk_LabelKey) && DecentRoot[sk_LabelKey].isString())
	{
		return DecentRoot[sk_LabelKey].asString();
	}
	throw MessageParseException();
}

std::string LoadWhiteList::ParseWhiteList(const Json::Value & DecentRoot)
{
	if (DecentRoot.isMember(sk_LabelWhiteList) && DecentRoot[sk_LabelWhiteList].isString())
	{
		return DecentRoot[sk_LabelWhiteList].asString();
	}
	throw MessageParseException();
}

LoadWhiteList::LoadWhiteList(const Json::Value & msg) :
	SmartMessages(msg, sk_ValueCat),
	m_key(ParseKey(msg[SmartMessages::sk_LabelRoot])),
	m_whiteList(ParseWhiteList(msg[SmartMessages::sk_LabelRoot]))
{
}

Json::Value & LoadWhiteList::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = SmartMessages::GetJsonMsg(outJson);

	parent[sk_LabelKey] = m_key;
	parent[sk_LabelWhiteList] = m_whiteList;

	return parent;
}

constexpr char RequestAppCert::sk_LabelRoot[];
constexpr char RequestAppCert::sk_ValueCat[];
constexpr char RequestAppCert::sk_LabelKey[];

std::string RequestAppCert::ParseKey(const Json::Value & DecentRoot)
{
	if (DecentRoot.isMember(sk_LabelKey) && DecentRoot[sk_LabelKey].isString())
	{
		return DecentRoot[sk_LabelKey].asString();
	}
	throw MessageParseException();
}

RequestAppCert::RequestAppCert(const Json::Value & msg) :
	SmartMessages(msg, sk_ValueCat),
	m_key(ParseKey(msg[SmartMessages::sk_LabelRoot]))
{
}

Json::Value & RequestAppCert::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = SmartMessages::GetJsonMsg(outJson);

	parent[sk_LabelKey] = m_key;

	return parent;
}
