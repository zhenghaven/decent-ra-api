#include "Loaded.h"

#ifdef ENCLAVE_ENVIRONMENT
#include <rapidjson/document.h>
#else
#include <json/json.h>
#endif // ENCLAVE_ENVIRONMENT

#include "../../Tools/JsonTools.h"
#include "../../Common.h"
#include "../../RuntimeException.h"

#include "../Crypto.h"

using namespace Decent::Ra;
using namespace Decent::Tools;
using namespace Decent::Ra::WhiteList;

WhiteListType Loaded::ParseWhiteListFromJson(const std::string & whiteListJson)
{
	WhiteListType res;
	if (whiteListJson.size() == 0)
	{
		return res;
	}

	JsonDoc doc;
	ParseStr2Json(doc, whiteListJson);
	if (!doc.JSON_IS_OBJECT())
	{
		throw Decent::RuntimeException("Failed to parse white list from JSON.");
	}

	for (auto it = doc.JSON_IT_BEGIN(); it != doc.JSON_IT_END(); ++it)
	{
		if (!JSON_IT_GETKEY(it).JSON_IS_STRING() || !JSON_IT_GETVALUE(it).JSON_IS_STRING())
		{
			throw Decent::RuntimeException("Failed to parse white list from JSON.");
		}
		res[JSON_IT_GETKEY(it).JSON_AS_STRING()] = JSON_IT_GETVALUE(it).JSON_AS_STRING();
	}
	return res;
}

Loaded::Loaded(const AppX509& certPtr) :
	Loaded(certPtr.GetWhiteList())
{
}

Loaded::Loaded(const std::string & whiteListJson) :
	Loaded(ParseWhiteListFromJson(whiteListJson))
{
}
