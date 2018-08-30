#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL

#pragma once

#include <string>
#include <utility>

class AESGCMCommLayer;

typedef bool(*SendFunctionType)(void* const connectionPtr, const char* senderID, const char *msg);

typedef struct _sgx_ec256_public_t sgx_ec256_public_t;
#define SGX_CMAC_KEY_SIZE               16
typedef uint8_t sgx_ec_key_128bit_t[SGX_CMAC_KEY_SIZE];

namespace SGXRAEnclave
{
	bool AddNewServerRAState(const std::string& ServerID, const sgx_ec256_public_t& inPubKey);
	void DropRAStateToServer(const std::string& serverID);
	bool IsAttestedToServer(const std::string& serverID);
	bool ReleaseServerKeys(const std::string& serverID, sgx_ec256_public_t* outSignPubKey, sgx_ec_key_128bit_t* outSK, sgx_ec_key_128bit_t* outMK);
	AESGCMCommLayer* ReleaseServerKeys(const std::string& serverID, SendFunctionType sendFunc);
}

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL
