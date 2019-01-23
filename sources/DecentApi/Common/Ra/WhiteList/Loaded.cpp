#include "Loaded.h"

#ifdef ENCLAVE_ENVIRONMENT
#include <rapidjson/document.h>
#else
#include <json/json.h>
#endif // ENCLAVE_ENVIRONMENT

#include "../../Tools/JsonTools.h"
#include "../../Common.h"

#include "../Crypto.h"

using namespace Decent::Ra;
using namespace Decent::Tools;
using namespace Decent::Ra::WhiteList;

WhiteListType Loaded::ParseWhiteListFromJson(const std::string & whiteListJson)
{
	//LOGI("Parsing Const WhiteList: \n%s \n", whiteListJson.c_str());
	WhiteListType res;
	if (whiteListJson.size() == 0)
	{
		return res;
	}

	JSON_EDITION::JSON_DOCUMENT_TYPE doc;
	if (!ParseStr2Json(doc, whiteListJson) ||
		!doc.JSON_IS_OBJECT())
	{
		return res;
	}

	for (auto it = doc.JSON_IT_BEGIN(); it != doc.JSON_IT_END(); ++it)
	{
		res[JSON_IT_GETKEY(it).JSON_AS_STRING()] = JSON_IT_GETVALUE(it).JSON_AS_STRING();
	}
	return res;
}

Loaded::Loaded(AppX509 * certPtr) :
	Loaded((certPtr && *certPtr) ? certPtr->GetWhiteList() : std::string())
{
}

Loaded::Loaded(const std::string & whiteListJson) :
	StaticTypeList(ParseWhiteListFromJson(whiteListJson))
{
}