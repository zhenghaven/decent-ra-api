#pragma once
#ifndef SGX_CRYPTO_TOOLS_H
#define SGX_CRYPTO_TOOLS_H

#include <stdint.h>
#include <sgx_error.h>

typedef struct _sgx_ec256_dh_shared_t sgx_ec256_dh_shared_t;

#define SGX_CMAC_KEY_SIZE               16
typedef uint8_t sgx_ec_key_128bit_t[SGX_CMAC_KEY_SIZE];

//SMK(SIGMA protocol)
//SK (Signing Key / Symmetric Key)
//MK (Master Key / Masking Key)
//VK (Verification key)
typedef enum _sgx_derive_key_type_t
{
	SGX_DERIVE_KEY_SMK = 0,
	SGX_DERIVE_KEY_SK,
	SGX_DERIVE_KEY_MK,
	SGX_DERIVE_KEY_VK,
} sgx_derive_key_type_t;

constexpr char SGX_SMK_KEY_LABEL_STR[] = "SMK";
constexpr char SGX_SK_KEY_LABEL_STR[] = "SK";
constexpr char SGX_MK_KEY_LABEL_STR[] = "MK";
constexpr char SGX_VK_KEY_LABEL_STR[] = "VK";

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

	sgx_status_t sp_derive_key(const sgx_ec256_dh_shared_t* shared_key, const char* label, uint32_t label_length, sgx_ec_key_128bit_t* derived_key);

	sgx_status_t sp_derive_key_type(const sgx_ec256_dh_shared_t* shared_key, sgx_derive_key_type_t type, sgx_ec_key_128bit_t* derived_key);

	sgx_status_t derive_key_set(const sgx_ec256_dh_shared_t* shared_key, sgx_ec_key_128bit_t* out_smk, sgx_ec_key_128bit_t* out_mk, sgx_ec_key_128bit_t* out_sk, sgx_ec_key_128bit_t* out_vk);

	sgx_status_t verify_cmac128(const sgx_ec_key_128bit_t* mac_key, const uint8_t* data_buf, uint32_t buf_size, const uint8_t* mac_buf);

#if !defined(ENCLAVE_CODE)
	int consttime_memequal(const void *b1, const void *b2, size_t len);
#endif // ENCLAVE_CODE


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // SGX_CRYPTO_TOOLS_H
