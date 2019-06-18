#include "EnclaveList.h"

#include <json/json.h>

#include "../../Common/Tools/JsonTools.h"
#include "../../Common/Ra/WhiteList/StaticList.h"

#include "../Tools/JsonParser.h"

using namespace Decent::Tools;
using namespace Decent::AppConfig;

namespace
{
	static std::string ParseHashStrOptional(const Decent::Tools::JsonValue & json, const std::string& label)
	{
		try
		{
			return Decent::Tools::JsonGetStringFromObject(json, label);
		}
		catch (const Decent::Tools::JsonParseError)
		{
			return std::string();
		}
	}
}

constexpr char const EnclaveListItem::sk_labelAddr[];
constexpr char const EnclaveListItem::sk_labelPort[];
constexpr char const EnclaveListItem::sk_labelIsLoadWl[];
constexpr char const EnclaveListItem::sk_labelHash[];

EnclaveListItem::EnclaveListItem(const Decent::Tools::JsonValue & json) :
	EnclaveListItem(Tools::JsonGetStringFromObject(json, sk_labelAddr),
		Tools::JsonGetIntFromObject(json, sk_labelPort),
		Tools::JsonGetBoolFromObject(json, sk_labelIsLoadWl),
		ParseHashStrOptional(json, sk_labelHash))
{
	if (m_loaddedWhiteList && m_hashStr.size() == 0)
	{
		throw Tools::JsonParseError();
	}
}

EnclaveListItem::~EnclaveListItem()
{
}

namespace
{
	static std::map<std::string, std::unique_ptr<EnclaveListItem> > ParseEnclaveListMap(const Json::Value& json)
	{
		std::map<std::string, std::unique_ptr<EnclaveListItem> > res;

		if (json.JSON_IS_OBJECT())
		{
			for (auto it = json.begin(); it != json.end(); ++it)
			{
				res.insert(
					std::make_pair(JsonGetString(JSON_IT_GETKEY(it)), std::make_unique<EnclaveListItem>(JSON_IT_GETVALUE(it)))
				);
			}
			return res;
		}

		throw Decent::Tools::JsonParseError();
	}

	static Decent::Ra::WhiteList::WhiteListType ConstructLoadedWhiteList(const std::map<std::string, std::unique_ptr<EnclaveListItem> >& configMap)
	{
		Decent::Ra::WhiteList::WhiteListType res;

		for (auto it = configMap.begin(); it != configMap.cend(); ++it)
		{
			const EnclaveListItem& item = *(it->second);
			if (item.GetIsLoaddedWhiteList())
			{
				res[item.GetHashStr()] = it->first;
			}
		}
		return res;
	}
}

constexpr char const EnclaveList::sk_defaultLabel[];

EnclaveList::EnclaveList(const Json::Value & json) :
	EnclaveList(ParseEnclaveListMap(json))
{
}

EnclaveList::~EnclaveList()
{
}

const EnclaveListItem * EnclaveList::GetItemPtr(const std::string name) const
{
	auto it = m_configMap.find(name);
	return it != m_configMap.cend() ? it->second.get() : nullptr;
}

const EnclaveListItem & EnclaveList::GetItem(const std::string name) const
{
	auto it = m_configMap.find(name);
	if (it != m_configMap.cend())
	{
		return *(it->second);
	}
	throw RuntimeException("Configuration for indicated app is not found!");
}

std::string EnclaveList::GetLoadedWhiteListStr() const
{
	return m_loadedWhiteList->ToJsonString();
}

EnclaveList::EnclaveList(std::map<std::string, std::unique_ptr<EnclaveListItem> > configMap) :
	m_configMap(std::move(configMap)),
	m_loadedWhiteList(std::make_unique<Ra::WhiteList::StaticList>(ConstructLoadedWhiteList(m_configMap)))
{
}
