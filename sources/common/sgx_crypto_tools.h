#pragma once
#ifndef SGX_CRYPTO_TOOLS_H
#define SGX_CRYPTO_TOOLS_H

#include <stdint.h>

typedef struct _sgx_ec256_dh_shared_t sgx_ec256_dh_shared_t;

#define SGX_CMAC_KEY_SIZE               16
typedef uint8_t sgx_ec_key_128bit_t[SGX_CMAC_KEY_SIZE];

//SMK(SIGMA protocol)
//SK (Signing Key / Symmetric Key)
//MK (Master Key / Masking Key)
//VK (Verification key)
typedef enum _sample_derive_key_type_t
{
	SAMPLE_DERIVE_KEY_SMK = 0,
	SAMPLE_DERIVE_KEY_SK,
	SAMPLE_DERIVE_KEY_MK,
	SAMPLE_DERIVE_KEY_VK,
} sample_derive_key_type_t;

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

bool sp_derive_key(const sgx_ec256_dh_shared_t *p_shared_key, uint8_t key_id, sgx_ec_key_128bit_t* derived_key);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // SGX_CRYPTO_TOOLS_H
