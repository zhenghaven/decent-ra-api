#pragma once

#include <string>

class RAKeyManager;

namespace DecentEnclave
{
	bool IsAttested(const std::string& id);

	const RAKeyManager* GetNodeKeyMgr(const std::string& id);
}