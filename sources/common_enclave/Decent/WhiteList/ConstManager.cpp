#include "ConstManager.h"

#include "../../../common/CommonTool.h"

using namespace Decent::WhiteList;

ConstManager & ConstManager::Get()
{
	static ConstManager inst;
	return inst;
}

Decent::WhiteList::ConstManager::ConstManager()
{
}

Decent::WhiteList::ConstManager::~ConstManager()
{
}

std::string Decent::WhiteList::ConstManager::GetWhiteList(const std::string & key) const
{
	std::unique_lock<std::mutex> listMapLock(m_listMapMutex);
	auto it = m_listMap.find(key);

	const bool isFound = it != m_listMap.cend();
	return isFound ? it ->second : std::string();
}

bool Decent::WhiteList::ConstManager::AddWhiteList(const std::string & key, const std::string & listJson)
{
	//Add validation code for "listJson" as necessary here.
	
	std::unique_lock<std::mutex> listMapLock(m_listMapMutex);
	m_listMap[key] = listJson;

	COMMON_PRINTF("Loaded Const WhiteList: Key = %s. \n%s \n", key.c_str(), listJson.c_str());

	return true;
}
