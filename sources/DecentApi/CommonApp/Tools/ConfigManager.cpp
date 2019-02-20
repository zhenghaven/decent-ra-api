#include "ConfigManager.h"

#include <json/json.h>

#include "../../Common/Tools/JsonTools.h"
#include "../../Common/Ra/WhiteList/StaticTypeList.h"

using namespace Decent::Tools;
using namespace Decent::Ra::WhiteList;

namespace
{
	static Json::Value ParseJsonStr(const std::string & jsonStr)
	{
		Json::Value res;
		return ParseStr2Json(res, jsonStr) ? std::move(res) : throw ConfigParseException();
	}

	static std::map<std::string, std::unique_ptr<ConfigItem> > ParseJson(const Json::Value& json)
	{
		std::map<std::string, std::unique_ptr<ConfigItem> > res;

		if (json.isObject())
		{
			for (auto it = json.begin(); it != json.end(); ++it)
			{
				res.insert(
					std::make_pair(std::string(JSON_IT_GETKEY(it).JSON_AS_STRING()), std::make_unique<ConfigItem>(JSON_IT_GETVALUE(it)))
				);
			}
			return std::move(res);
		}
		throw ConfigParseException();
	}

	static std::string ParseString(const Json::Value & json)
	{
		if (json.JSON_IS_STRING())
		{
			return json.JSON_AS_STRING();
		}
		throw ConfigParseException();
	}

	static std::string ParseAddr(const Json::Value & json)
	{
		if (json.JSON_IS_OBJECT() && json.JSON_HAS_MEMBER(ConfigItem::sk_labelAddr))
		{
			return ParseString(json[ConfigItem::sk_labelAddr]);
		}
		throw ConfigParseException();
	}

	static std::string ParseHashStr(const Json::Value & json)
	{
		if (json.JSON_IS_OBJECT() && json.JSON_HAS_MEMBER(ConfigItem::sk_labelHash))
		{
			return ParseString(json[ConfigItem::sk_labelHash]);
		}
		throw ConfigParseException();
	}

	static uint16_t ParsePort(const Json::Value & json)
	{
		if (json.JSON_IS_OBJECT() && json.JSON_HAS_MEMBER(ConfigItem::sk_labelPort))
		{
			const Json::Value& child = json[ConfigItem::sk_labelPort];
			if (child.JSON_IS_INT())
			{
				return child.JSON_AS_INT32();
			}
		}
		throw ConfigParseException();
	}

	static bool ParseIsLoaddedList(const Json::Value & json)
	{
		if (json.JSON_IS_OBJECT() && json.JSON_HAS_MEMBER(ConfigItem::sk_labelIsLoadWl))
		{
			const Json::Value& child = json[ConfigItem::sk_labelIsLoadWl];
			if (child.JSON_IS_BOOL())
			{
				return child.JSON_AS_BOOL();
			}
		}
		throw ConfigParseException();
	}

	static WhiteListType ConstructLoadedWhiteList(const std::map<std::string, std::unique_ptr<ConfigItem> >& configMap)
	{
		WhiteListType res;
		for (auto it = configMap.begin(); it != configMap.cend(); ++it)
		{
			const ConfigItem& item = *(it->second);
			if (item.GetIsLoaddedWhiteList())
			{
				res[it->first] = item.GetHashStr();
			}
		}
		return std::move(res);
	}

	static std::string ConstructLoadedWhiteListStr(const WhiteListType& whiteList)
	{
		StaticTypeList statWhiteList(whiteList);

		JsonDoc jsonDoc;
		statWhiteList.ToJson(jsonDoc);
		return Json2String(jsonDoc);
	}
}

constexpr char const ConfigItem::sk_labelAddr[];
constexpr char const ConfigItem::sk_labelPort[];
constexpr char const ConfigItem::sk_labelIsLoadWl[];

ConfigItem::ConfigItem(const Json::Value & json) :
	ConfigItem(ParseAddr(json), ParsePort(json), ParseIsLoaddedList(json), json)
{
}

ConfigItem::ConfigItem(std::string&& addr, const uint16_t port, const bool isLoaddedList, const Json::Value & json) :
	ConfigItem(addr, port, isLoaddedList, isLoaddedList ? ParseHashStr(json) : "")
{
}

ConfigManager::ConfigManager(const std::string & jsonStr) :
	ConfigManager(ParseJsonStr(jsonStr))
{
}

ConfigManager::ConfigManager(const Json::Value & json) :
	ConfigManager(ParseJson(json))
{
}

ConfigManager::~ConfigManager()
{
}

const ConfigItem * Decent::Tools::ConfigManager::GetItemPtr(const std::string name) const
{
	auto it = m_configMap.find(name);
	return it != m_configMap.cend() ? it->second.get() :  nullptr;
}

const ConfigItem & Decent::Tools::ConfigManager::GetItem(const std::string name) const
{
	auto it = m_configMap.find(name);
	if (it != m_configMap.cend())
	{
		return *(it->second);
	}
	throw std::runtime_error("Configuration for indicated app is not found!");
}

ConfigManager::ConfigManager(std::map<std::string, std::unique_ptr<ConfigItem> >&& configMap) :
	m_configMap(std::forward<std::map<std::string, std::unique_ptr<ConfigItem> > >(configMap)),
	m_loadedWhiteListStr(ConstructLoadedWhiteListStr(ConstructLoadedWhiteList(m_configMap)))
{
}
