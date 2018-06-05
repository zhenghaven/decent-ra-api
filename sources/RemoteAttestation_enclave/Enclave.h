#pragma once

#if defined(__cplusplus)
extern "C" {
#endif

void enclave_printf(const char *fmt, ...);

#if defined(__cplusplus)
}
#endif

#define SGX_QUOTE_UNLINKABLE_SIGNATURE 0
#define SGX_QUOTE_LINKABLE_SIGNATURE   1

#define SAMPLE_EC_MAC_SIZE 16
#define SAMPLE_SP_IV_SIZE        12

//Key Derivation Function ID : 0x0001  AES-CMAC Entropy Extraction and Key Expansion
constexpr uint16_t SAMPLE_AES_CMAC_KDF_ID = 0x0001;

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

bool derive_key(const sgx_ec256_dh_shared_t *p_shared_key, uint8_t key_id, sgx_ec_key_128bit_t* derived_key);