#include "StaticTypeList.h"

#include <algorithm>

#include "../../Common.h"

using namespace Decent::Ra::WhiteList;

StaticTypeList::StaticTypeList(const WhiteListType & whiteList) :
	m_listMap(whiteList)
{
	LOGI("Constrcuted Static WhiteList (Size = %llu): \n", m_listMap.size());
	for (auto it = m_listMap.cbegin(); it != m_listMap.cend(); ++it)
	{
		LOGI("\t - %s : %s \n", it->first.c_str(), it->second.c_str());
	}
	LOGI("Static WhiteList End. \n\n");
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
	auto it = m_listMap.find(hashStr);
	if (it != m_listMap.cend())
	{
		outAppName = it->second;
		return true;
	}
	return false;
}

bool Decent::Ra::WhiteList::StaticTypeList::CheckHashAndName(const std::string & hashStr, const std::string & appName) const
{
	auto it = m_listMap.find(hashStr);
	
	return (it != m_listMap.cend()) && (it->second == appName);
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

bool Decent::Ra::WhiteList::StaticTypeList::operator>=(const StaticTypeList & other) const
{
	return CheckListsWithinRange(other.m_listMap);
}
