#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENTRALIZED_ENCLAVE_INTERNAL

#pragma once

#include <string>

class AESGCMCommLayer;

typedef bool(*SendFunctionType)(void* const connectionPtr, const char* senderID, const char *msg, const char* appAttach);

typedef struct _sgx_ec256_public_t sgx_ec256_public_t;
#define SGX_CMAC_KEY_SIZE               16
typedef uint8_t sgx_ec_key_128bit_t[SGX_CMAC_KEY_SIZE];

namespace SGXRADecentralized
{
	void DropNode(const std::string& nodeID);
	bool IsNodeAttested(const std::string& nodeID);
	bool ReleaseNodeKeys(const std::string& nodeID, sgx_ec256_public_t* outSignPubKey, sgx_ec_key_128bit_t* outSK, sgx_ec_key_128bit_t* outMK);
	AESGCMCommLayer* ReleaseNodeKeys(const std::string& nodeID, SendFunctionType sendFunc);
}

#endif // USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENTRALIZED_ENCLAVE_INTERNAL
