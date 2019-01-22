#include "ConstManager.h"

#include "../../../Common/Common.h"

using namespace Decent::Ra::WhiteList;

ConstManager & ConstManager::Get()
{
	static ConstManager inst;
	return inst;
}

ConstManager::ConstManager()
{
}

ConstManager::~ConstManager()
{
}

std::string ConstManager::GetWhiteList(const std::string & key) const
{
	std::unique_lock<std::mutex> listMapLock(m_listMapMutex);
	auto it = m_listMap.find(key);

	const bool isFound = it != m_listMap.cend();
	return isFound ? it ->second : std::string();
}

bool ConstManager::AddWhiteList(const std::string & key, const std::string & listJson)
{
	//Add validation code for "listJson" as necessary here.
	
	std::unique_lock<std::mutex> listMapLock(m_listMapMutex);
	m_listMap[key] = listJson;

	LOGI("Loaded Const WhiteList: Key = %s. \n%s \n", key.c_str(), listJson.c_str());

	return true;
}
