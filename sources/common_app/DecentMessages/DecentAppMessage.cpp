#include "DecentAppMessage.h"

#include <json/json.h>

#include "../MessageException.h"

constexpr char DecentLoadWhiteList::sk_LabelRoot[];
constexpr char DecentLoadWhiteList::sk_ValueCat[];
constexpr char DecentLoadWhiteList::sk_LabelKey[];
constexpr char DecentLoadWhiteList::sk_LabelWhiteList[];

std::string DecentLoadWhiteList::ParseKey(const Json::Value & DecentRoot)
{
	if (DecentRoot.isMember(sk_LabelKey) && DecentRoot[sk_LabelKey].isString())
	{
		return DecentRoot[sk_LabelKey].asString();
	}
	throw MessageParseException();
}

std::string DecentLoadWhiteList::ParseWhiteList(const Json::Value & DecentRoot)
{
	if (DecentRoot.isMember(sk_LabelWhiteList) && DecentRoot[sk_LabelWhiteList].isString())
	{
		return DecentRoot[sk_LabelWhiteList].asString();
	}
	throw MessageParseException();
}

DecentLoadWhiteList::DecentLoadWhiteList(const Json::Value & msg) :
	Messages(msg, sk_ValueCat),
	m_key(ParseKey(msg[Messages::sk_LabelRoot])),
	m_whiteList(ParseWhiteList(msg[Messages::sk_LabelRoot]))
{
}

Json::Value & DecentLoadWhiteList::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = Messages::GetJsonMsg(outJson);

	parent[sk_LabelKey] = m_key;
	parent[sk_LabelWhiteList] = m_whiteList;

	return parent;
}

constexpr char DecentRequestAppCert::sk_LabelRoot[];
constexpr char DecentRequestAppCert::sk_ValueCat[];
constexpr char DecentRequestAppCert::sk_LabelKey[];

std::string DecentRequestAppCert::ParseKey(const Json::Value & DecentRoot)
{
	if (DecentRoot.isMember(sk_LabelKey) && DecentRoot[sk_LabelKey].isString())
	{
		return DecentRoot[sk_LabelKey].asString();
	}
	throw MessageParseException();
}

DecentRequestAppCert::DecentRequestAppCert(const Json::Value & msg) :
	Messages(msg, sk_ValueCat),
	m_key(ParseKey(msg[Messages::sk_LabelRoot]))
{
}

Json::Value & DecentRequestAppCert::GetJsonMsg(Json::Value & outJson) const
{
	Json::Value& parent = Messages::GetJsonMsg(outJson);

	parent[sk_LabelKey] = m_key;

	return parent;
}
