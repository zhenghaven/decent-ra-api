#include "ServerConfigManager.h"

#include <json/json.h>

#include "../Common/Tools/JsonTools.h"

using namespace Decent::Tools;
using namespace Decent::Ra::WhiteList;

namespace
{
	static Json::Value ParseJsonStr(const std::string & jsonStr)
	{
		try
		{
			Json::Value res;
			ParseStr2Json(res, jsonStr);
			return std::move(res);
		}
		catch (const std::exception&)
		{
			throw ConfigParseException();
		}
	}

	static std::string ParseString(const Json::Value & json)
	{
		return json.JSON_IS_STRING() ? json.JSON_AS_STRING() : throw ConfigParseException();
	}

	static std::string ParseStringObject(const Json::Value & json, const char* key)
	{
		return json.JSON_IS_OBJECT() && json.JSON_HAS_MEMBER(key) ?
			ParseString(json[key]) :
			throw ConfigParseException();
	}

	static std::string ParseSpCertPath(const Json::Value & json)
	{
		try
		{
			return ParseStringObject(json, ServerConfigManager::sk_labelSpCertPath);
		}
		catch (const ConfigParseException&)
		{
			return std::string();
		}
	}

	static std::string ParseSpPrvKeyPath(const Json::Value & json)
	{
		try
		{
			return ParseStringObject(json, ServerConfigManager::sk_labelSpPrvKeyPath);
		}
		catch (const ConfigParseException&)
		{
			return std::string();
		}
	}
}

constexpr char const ServerConfigManager::sk_labelSpCertPath[];
constexpr char const ServerConfigManager::sk_labelSpPrvKeyPath[];

ServerConfigManager::ServerConfigManager(const std::string & jsonStr) :
	ServerConfigManager(ParseJsonStr(jsonStr))
{
}

ServerConfigManager::ServerConfigManager(const Json::Value & json) :
	ConfigManager(json),
	m_spCertPath(ParseSpCertPath(json)),
	m_spPrvKeyPath(ParseSpPrvKeyPath(json))
{
}

ServerConfigManager::~ServerConfigManager()
{
}
