#include <map>

#include "../../common_enclave/RAConnection.h"
#include "../../common_enclave/RAKeyManager.h"
#include "../../common_enclave/sgx_ra_tools.h"

namespace
{
	std::map<std::string, std::pair<ServerRAState, RAKeyManager> > g_serversMap;

}

sgx_status_t ecall_process_ra_msg0_resp(const char* ServerID, const sgx_ec256_public_t* inPubKey, int enablePSE, sgx_ra_context_t* outContextID)
{
	auto it = g_serversMap.find(ServerID);
	if (it != g_serversMap.end())
	{
		return SGX_ERROR_UNEXPECTED;
	}
	g_serversMap.insert(std::make_pair<std::string, std::pair<ServerRAState, RAKeyManager> >(ServerID, std::make_pair<ServerRAState, RAKeyManager>(ServerRAState::MSG0_DONE, RAKeyManager(*inPubKey))));

	return enclave_init_ra(inPubKey, enablePSE, outContextID);
}
