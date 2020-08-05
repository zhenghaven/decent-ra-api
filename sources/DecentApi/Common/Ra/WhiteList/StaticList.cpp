#include "StaticList.h"

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

StaticList::StaticList(const WhiteListType & whiteList) :
	m_listMap(whiteList)
{
//#ifdef DEBUG
//	LOGI("Constrcuted Static WhiteList (Size = %llu):", m_listMap.size());
//	for (auto it = m_listMap.cbegin(); it != m_listMap.cend(); ++it)
//	{
//		LOGI("\t%s\t:\t%s", it->first.c_str(), it->second.c_str());
//	}
//	LOGI("Static WhiteList End. \n");
//#endif // DEBUG
}

StaticList::StaticList(WhiteListType && whiteList) :
	m_listMap(std::forward<WhiteListType>(whiteList))
{
//#ifdef DEBUG
//	LOGI("Constrcuted Static WhiteList (Size = %llu):", m_listMap.size());
//	for (auto it = m_listMap.cbegin(); it != m_listMap.cend(); ++it)
//	{
//		LOGI("\t%s\t:\t%s", it->first.c_str(), it->second.c_str());
//	}
//	LOGI("Static WhiteList End. \n");
//#endif // DEBUG
}

StaticList::StaticList(const StaticList & rhs) :
	m_listMap(rhs.m_listMap)
{}

StaticList::StaticList(StaticList && rhs) :
	m_listMap(std::forward<WhiteListType>(rhs.m_listMap))
{}

StaticList::~StaticList()
{
}

const WhiteListType & StaticList::GetMap() const
{
	return m_listMap;
}

bool StaticList::CheckHash(const std::string & hashStr, std::string & outAppName) const
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

bool StaticList::CheckHashAndName(const std::string & hashStr, const std::string & appName) const
{
#ifndef DEBUG
	auto it = m_listMap.find(hashStr);

	if ((it != m_listMap.cend()) && (it->second == appName))
	{
		return true;
	}
	else
	{
		LOGW("Peer <%s, %s> is not in the AuthList.", hashStr.c_str(), appName.c_str());
		return false;
	}
#else
	LOGW("%s() passed app, %s, with hash, %s,  without checking!", __FUNCTION__, appName.c_str(), hashStr.c_str());
	return true;
#endif // !DEBUG

}

bool StaticList::IsEquivalentSetOf(const WhiteListType & otherMap) const
{
	return (m_listMap.size() == otherMap.size()) && //Quick pre-check: two sets must have the same size.
		std::equal(m_listMap.begin(), m_listMap.end(), otherMap.begin());
}

bool StaticList::IsSubsetOf(const WhiteListType & rhs) const
{//Check if 'this instance' is a subset of 'rhs'.

	// Quick pre-check:
	// 'this' is a subset, so, its size must <= (i.e. smaller or equal) to 'rhs'.
	if (this->m_listMap.size() > rhs.size())
	{
		return false;
	}

	return std::includes(rhs.begin(), rhs.end(), this->m_listMap.begin(), this->m_listMap.end());
}

bool StaticList::operator==(const StaticList & rhs) const
{
	return IsEquivalentSetOf(rhs);
}

bool StaticList::operator!=(const StaticList & rhs) const
{
	return !(*this == rhs);
}

bool StaticList::operator>=(const StaticList & rhs) const
{
	return (rhs <= *this);
}

bool StaticList::operator<=(const StaticList & rhs) const
{
	return this->IsSubsetOf(rhs);
}

std::string StaticList::ToJsonString() const
{
	JsonDoc jsonDoc;

	for (auto it = m_listMap.begin(); it != m_listMap.end(); ++it)
	{
		JsonSetVal(jsonDoc, it->first, it->second);
	}

	return Tools::Json2String(jsonDoc);
}
