#include "LoadedList.h"

#ifdef ENCLAVE_ENVIRONMENT
#include <rapidjson/document.h>
#else
#include <json/json.h>
#endif // ENCLAVE_ENVIRONMENT

#include <cppcodec/base64_default_rfc4648.hpp>
#include <mbedTLScpp/Hash.hpp>

#include "../../Common.h"
#include "../../Exceptions.h"
#include "../../Tools/JsonTools.h"

using namespace Decent::Ra;
using namespace Decent::Tools;
using namespace Decent::Ra::WhiteList;

namespace
{
	std::string ConstructWhiteListHashString(const WhiteListType & whiteList)
	{
		using namespace mbedTLScpp;

		std::string whiteListStr = "DecentWhiteList{";
		for (auto it = whiteList.begin(); it != whiteList.end(); ++it)
		{
			whiteListStr += (it->first + "::" + it->second);
		}
		whiteListStr += "}";

		Hash<HashType::SHA256> hash = Hasher<HashType::SHA256>().Calc(CtnFullR(whiteListStr));

		return cppcodec::base64_rfc4648::encode(hash);
	}
}

WhiteListType LoadedList::ParseWhiteListFromJson(const std::string & whiteListJson)
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
		throw Decent::InvalidArgumentException("Ra::WhiteList::LoadedList::ParseWhiteListFromJson - Failed to parse AuthList from JSON.");
	}

	for (auto it = doc.JSON_IT_BEGIN(); it != doc.JSON_IT_END(); ++it)
	{
		if (!JSON_IT_GETKEY(it).JSON_IS_STRING() || !JSON_IT_GETVALUE(it).JSON_IS_STRING())
		{
			throw Decent::InvalidArgumentException("Ra::WhiteList::LoadedList::ParseWhiteListFromJson - Failed to parse AuthList from JSON.");
		}
		res[JSON_IT_GETKEY(it).JSON_AS_STRING()] = JSON_IT_GETVALUE(it).JSON_AS_STRING();
	}
	return res;
}

LoadedList::LoadedList() :
	StaticList(WhiteListType()),
	m_listHash(ConstructWhiteListHashString(StaticList::GetMap()))
{}

LoadedList::LoadedList(const WhiteListType& whiteList) :
	StaticList(whiteList),
	m_listHash(ConstructWhiteListHashString(whiteList))
{}

LoadedList::LoadedList(WhiteListType&& whiteList) :
	StaticList(std::forward<WhiteListType>(whiteList)),
	m_listHash(ConstructWhiteListHashString(StaticList::GetMap()))
{}
