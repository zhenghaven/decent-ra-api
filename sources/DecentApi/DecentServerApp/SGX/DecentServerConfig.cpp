#include "DecentServerConfig.h"

#include <json/json.h>

#include "../../Common/Tools/JsonTools.h"
#include "../../CommonApp/Tools/JsonParser.h"

using namespace Decent::Tools;
using namespace Decent::Sgx;

namespace
{
	static Json::Value ParseJsonStr(const std::string & jsonStr)
	{
		Json::Value res;
		ParseStr2Json(res, jsonStr);
		return std::move(res);
	}
}

constexpr char const DecentServerConfig::sk_labelDecentServerEnclave[];

DecentServerConfig::DecentServerConfig(const std::string & jsonStr) :
	DecentServerConfig(ParseJsonStr(jsonStr))
{
}

DecentServerConfig::DecentServerConfig(const Json::Value & json) :
	m_decentSvr(JsonGetValue(json, sk_labelDecentServerEnclave)),
	m_svcProv(JsonGetValue(json, AppConfig::SgxServiceProvider::sk_defaultLabel))
{
}

DecentServerConfig::~DecentServerConfig()
{
}

