#include "ServerConfigManager.h"

#include <json/json.h>
#include <sgx_quote.h>
#include <cppcodec/hex_default_upper.hpp>

#include "../Common/Tools/JsonTools.h"
#include "../Common/Ra/WhiteList/HardCoded.h"

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

	static const Json::Value& GetJsonDecentServerRoot(const Json::Value & json)
	{
		if (json.isMember(sk_nameDecentServer))
		{
			return json[sk_nameDecentServer];
		}
		throw ConfigParseException();
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

	static std::unique_ptr<sgx_spid_t> ParseSpid(const Json::Value & json)
	{
		std::unique_ptr<sgx_spid_t> res = std::make_unique<sgx_spid_t>();
		std::string spidStr;
#ifdef SIMULATING_ENCLAVE
		try
		{
#endif // SIMULATING_ENCLAVE
			spidStr = ParseStringObject(json, ServerConfigManager::sk_labelSpid);
#ifdef SIMULATING_ENCLAVE
		}
		catch (const ConfigParseException&)
		{
			return std::move(res);
		}
#endif // SIMULATING_ENCLAVE
		if (sizeof(sgx_spid_t) != cppcodec::hex_upper::decoded_max_size(spidStr.size()))
		{
			throw ConfigParseException();
		}
		cppcodec::hex_upper::decode(reinterpret_cast<char*>(res.get()), sizeof(sgx_spid_t), spidStr);
		return std::move(res);
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
constexpr char const ServerConfigManager::sk_labelSpid[];

ServerConfigManager::ServerConfigManager(const std::string & jsonStr) :
	ServerConfigManager(ParseJsonStr(jsonStr))
{
}

ServerConfigManager::ServerConfigManager(const Json::Value & json) :
	ServerConfigManager(json, GetJsonDecentServerRoot(json))
{
}

ServerConfigManager::~ServerConfigManager()
{
}

ServerConfigManager::ServerConfigManager(const Json::Value & root, const Json::Value & server) :
	ConfigManager(root),
	m_spid(ParseSpid(server)),
	m_spCertPath(ParseSpCertPath(server)),
	m_spPrvKeyPath(ParseSpPrvKeyPath(server))
{
}
