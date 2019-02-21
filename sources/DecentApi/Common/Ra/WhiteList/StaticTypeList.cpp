#include "StaticTypeList.h"

#include <algorithm>

#ifdef ENCLAVE_ENVIRONMENT
#include <rapidjson/document.h>
#else
#include <json/json.h>
#endif

#include "../../Common.h"
#include "../../Tools/JsonTools.h"

using namespace Decent::Ra::WhiteList;
using namespace Decent::Tools;

StaticTypeList::StaticTypeList(const WhiteListType & whiteList) :
	m_listMap(whiteList)
{
#ifdef DEBUG
	LOGI("Constrcuted Static WhiteList (Size = %llu):", m_listMap.size());
	for (auto it = m_listMap.cbegin(); it != m_listMap.cend(); ++it)
	{
		LOGI("\t%s\t:\t%s", it->first.c_str(), it->second.c_str());
	}
	LOGI("Static WhiteList End. \n");
#endif // DEBUG
}

StaticTypeList::~StaticTypeList()
{
}

const WhiteListType & StaticTypeList::GetMap() const
{
	return m_listMap;
}

bool StaticTypeList::CheckHash(const std::string & hashStr, std::string & outAppName) const
{
#ifndef DEBUG
	auto it = m_listMap.find(hashStr);
	if (it != m_listMap.cend())
	{
		outAppName = it->second;
		return true;
	}
	return false;
#else
	LOGW("%s() passed app with hash, %s,  without checking!", __FUNCTION__, hashStr.c_str());
	return true;
#endif
}

bool StaticTypeList::CheckHashAndName(const std::string & hashStr, const std::string & appName) const
{
#ifndef DEBUG
	auto it = m_listMap.find(hashStr);

	return (it != m_listMap.cend()) && (it->second == appName);
#else
	LOGW("%s() passed app, %s, with hash, %s,  without checking!", __FUNCTION__, appName.c_str(), hashStr.c_str());
	return true;
#endif // !DEBUG

}

bool StaticTypeList::CheckListsAreMatch(const WhiteListType & otherMap) const
{
	return (m_listMap.size() == otherMap.size()) &&
		std::equal(m_listMap.begin(), m_listMap.end(), otherMap.begin());
}

bool Decent::Ra::WhiteList::StaticTypeList::CheckListsWithinRange(const WhiteListType & otherMap) const
{
	if (m_listMap.size() < otherMap.size())
	{
		return false;
	}

	for (auto ito = otherMap.begin(), ita = m_listMap.begin(); ito != otherMap.cend() && ita != m_listMap.cend(); ++ito)
	{
		while (ito->first != ita->first && (++ita) != m_listMap.cend())
		{
		}

		if (ita == m_listMap.cend() ||
			ito->second != ita->second)
		{
			return false;
		}
	}
	return true;
}

bool StaticTypeList::operator==(const StaticTypeList & other) const
{
	return CheckListsAreMatch(other.m_listMap);
}

bool StaticTypeList::operator!=(const StaticTypeList & other) const
{
	return !(*this == other);
}

bool StaticTypeList::operator>=(const StaticTypeList & other) const
{
	return CheckListsWithinRange(other.m_listMap);
}

JsonValue & StaticTypeList::ToJson(JsonDoc & jsonDoc) const
{
	for (auto it = m_listMap.begin(); it != m_listMap.end(); ++it)
	{
		JsonSetVal(jsonDoc, it->first, it->second);
	}
	return jsonDoc;
}
