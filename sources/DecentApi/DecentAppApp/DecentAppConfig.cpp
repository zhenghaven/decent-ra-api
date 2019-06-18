#include "DecentAppConfig.h"

#include <json/json.h>

#include "../Common/Tools/JsonTools.h"
#include "../CommonApp/Tools/JsonParser.h"

using namespace Decent::Tools;
using namespace Decent::AppConfig;

namespace
{
	static Json::Value ParseJsonStr(const std::string & jsonStr)
	{
		Json::Value res;
		ParseStr2Json(res, jsonStr);
		return std::move(res);
	}
}

DecentAppConfig::DecentAppConfig(const std::string & jsonStr) :
	DecentAppConfig(ParseJsonStr(jsonStr))
{
}

DecentAppConfig::DecentAppConfig(const Json::Value & json) :
	m_enclaveList(JsonGetValue(json, EnclaveList::sk_defaultLabel))
{
}

DecentAppConfig::~DecentAppConfig()
{
}
