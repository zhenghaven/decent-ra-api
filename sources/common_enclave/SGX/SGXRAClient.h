#pragma once

#include <string>
#include <utility>

class RAKeyManager;
typedef struct _sgx_ec256_public_t sgx_ec256_public_t;

namespace SGXRAEnclave
{
	bool AddNewServerRAState(const std::string& ServerID, const sgx_ec256_public_t& inPubKey);
	void DropServerRAState(const std::string& serverID);
	bool IsServerAttested(const std::string& serverID);
	RAKeyManager* GetServerKeysMgr(const std::string& serverID);
}
