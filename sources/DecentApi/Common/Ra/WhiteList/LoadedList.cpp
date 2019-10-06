#include "LoadedList.h"

#ifdef ENCLAVE_ENVIRONMENT
#include <rapidjson/document.h>
#else
#include <json/json.h>
#endif // ENCLAVE_ENVIRONMENT

#include <cppcodec/base64_default_rfc4648.hpp>

#include "../../Common.h"
#include "../../RuntimeException.h"
#include "../../GeneralKeyTypes.h"
#include "../../Tools/JsonTools.h"
#include "../../MbedTls/Hasher.h"

#include "../AppX509Cert.h"

using namespace Decent::Ra;
using namespace Decent::Tools;
using namespace Decent::Ra::WhiteList;

namespace
{
	std::string ConstructWhiteListHashString(const WhiteListType & whiteList)
	{
		using namespace Decent::MbedTlsObj;

		std::string whiteListStr = "DecentWhiteList{";
		for (auto it = whiteList.begin(); it != whiteList.end(); ++it)
		{
			whiteListStr += (it->first + "::" + it->second);
		}
		whiteListStr += "}";

		Decent::General256Hash hash;
		Hasher<HashType::SHA256>().Calc(hash, whiteListStr);

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

LoadedList::LoadedList() :
	StaticList(WhiteListType()),
	m_listHash(ConstructWhiteListHashString(StaticList::GetMap()))
{}

LoadedList::LoadedList(LoadedList* instPtr) :
	LoadedList(instPtr ? std::move(*instPtr) : LoadedList())
{}

LoadedList::LoadedList(const WhiteListType& whiteList) :
	StaticList(whiteList),
	m_listHash(ConstructWhiteListHashString(whiteList))
{}

LoadedList::LoadedList(WhiteListType&& whiteList) :
	StaticList(std::forward<WhiteListType>(whiteList)),
	m_listHash(ConstructWhiteListHashString(StaticList::GetMap()))
{}

LoadedList::LoadedList(const LoadedList& rhs) :
	StaticList(rhs),
	m_listHash(rhs.m_listHash)
{}

LoadedList::LoadedList(LoadedList&& rhs) :
	StaticList(std::forward<StaticList>(rhs)),
	m_listHash(std::forward<std::string>(rhs.m_listHash))
{}

LoadedList::LoadedList(const AppX509Cert& certPtr) :
	LoadedList(certPtr.GetWhiteList())
{
}

LoadedList::LoadedList(const std::string & whiteListJson) :
	LoadedList(ParseWhiteListFromJson(whiteListJson))
{
}
