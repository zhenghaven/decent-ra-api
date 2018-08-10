#pragma once

#include <string>
#include <utility>
//#include "../common_enclave/RAKeyManager.h"
class RAKeyManager;

namespace SGXRAEnclave
{
	void DropServerRAState(const std::string& serverID);
	bool IsServerAttested(const std::string& serverID);
	//RAKeyManager&& ReleaseServerKeysMgr(const std::string& serverID);
	RAKeyManager* GetServerKeysMgr(const std::string& serverID);
}
