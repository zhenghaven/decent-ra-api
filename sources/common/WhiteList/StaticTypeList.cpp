#include "StaticTypeList.h"

#include <algorithm>

#include "../CommonTool.h"

using namespace Decent::WhiteList;

StaticTypeList::StaticTypeList(const WhiteListType & whiteList) :
	m_listMap(whiteList)
{
	COMMON_PRINTF("Constrcuted Static WhiteList (Size = %llu): \n", m_listMap.size());
	for (auto it = m_listMap.cbegin(); it != m_listMap.cend(); ++it)
	{
		COMMON_PRINTF("\t - %s : %s \n", it->first.c_str(), it->second.c_str());
	}
	COMMON_PRINTF("Static WhiteList End. \n\n");
}

StaticTypeList::~StaticTypeList()
{
}

const WhiteListType & StaticTypeList::GetMap() const
{
	return m_listMap;
}

bool StaticTypeList::CheckWhiteList(const std::string & hashStr, std::string & outAppName) const
{
	for (auto it = m_listMap.cbegin(); it != m_listMap.cend(); ++it)
	{
		if (it->second == hashStr)
		{
			outAppName = it->first;
			return true;
		}
	}
	return false;
}

bool StaticTypeList::CheckWhiteListWithHint(const std::string & hashStr, const std::string & hintAppName) const
{
	auto it = m_listMap.find(hintAppName);
	
	return (it != m_listMap.cend() && it->second == hashStr);
}

bool StaticTypeList::CheckListsAreMatch(const WhiteListType & otherMap) const
{
	return (m_listMap.size() == otherMap.size()) &&
		std::equal(m_listMap.begin(), m_listMap.end(), otherMap.begin());
}

bool StaticTypeList::GetHash(const std::string & appName, std::string & outHash) const
{
	auto it = m_listMap.find(appName);
	if (it != m_listMap.cend())
	{
		outHash = it->second;
		return true;
	}
	return false;
}

bool Decent::WhiteList::StaticTypeList::operator==(const StaticTypeList & other) const
{
	return CheckListsAreMatch(other.m_listMap);
}

bool Decent::WhiteList::StaticTypeList::operator!=(const StaticTypeList & other) const
{
	return !(*this == other);
}
