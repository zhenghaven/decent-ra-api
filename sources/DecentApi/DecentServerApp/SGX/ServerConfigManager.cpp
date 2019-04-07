#include "ServerConfigManager.h"

#include <json/json.h>
#include <sgx_quote.h>
#include <cppcodec/hex_default_upper.hpp>

#include "../../Common/Tools/JsonTools.h"

using namespace Decent;
using namespace Decent::Sgx;
using namespace Decent::Ra::WhiteList;

namespace
{
	static Json::Value ParseJsonStr(const std::string & jsonStr)
	{
		try
		{
			Json::Value res;
			Tools::ParseStr2Json(res, jsonStr);
			return std::move(res);
		}
		catch (const std::exception&)
		{
			throw Tools::ConfigParseException();
		}
	}

	static std::string ParseString(const Json::Value & json)
	{
		return json.JSON_IS_STRING() ? json.JSON_AS_STRING() : throw Tools::ConfigParseException();
	}

	static std::string ParseStringObject(const Json::Value & json, const char* key)
	{
		return json.JSON_IS_OBJECT() && json.JSON_HAS_MEMBER(key) ?
			ParseString(json[key]) :
			throw Tools::ConfigParseException();
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
			throw Tools::ConfigParseException();
		}
		cppcodec::hex_upper::decode(reinterpret_cast<char*>(res.get()), sizeof(sgx_spid_t), spidStr);
		return std::move(res);
	}
}

constexpr char const ServerConfigManager::sk_labelSpid[];

ServerConfigManager::ServerConfigManager(const std::string & jsonStr) :
	Sgx::ServerConfigManager(ParseJsonStr(jsonStr))
{
}

ServerConfigManager::ServerConfigManager(const Json::Value & json) :
	Tools::ServerConfigManager(json),
	m_spid(ParseSpid(json))
{
}

ServerConfigManager::~ServerConfigManager()
{
}
