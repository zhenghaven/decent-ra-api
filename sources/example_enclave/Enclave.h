#pragma once

#if defined(__cplusplus)
extern "C" {
#endif

void enclave_printf(const char *fmt, ...);

#if defined(__cplusplus)
}
#endif

std::string SerializePubKey(const sgx_ec256_public_t* pubKey);