#pragma once

#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL

#include <string>

typedef struct _sgx_dh_session_enclave_identity_t sgx_dh_session_enclave_identity_t;
#define SGX_CMAC_KEY_SIZE               16
typedef uint8_t sgx_ec_key_128bit_t[SGX_CMAC_KEY_SIZE];

namespace SGXLAEnclave
{
	void DropPeer(const std::string & peerId);
	bool ReleasePeerKey(const std::string & peerId, sgx_dh_session_enclave_identity_t& outIdentity, sgx_ec_key_128bit_t& outKey);
}

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL
