#include "sgx_crypto_tools.h"

#include <cstring>
#include <cstdlib>

#include <sgx_error.h>
#include <sgx_tcrypto.h>

#define EC_DERIVATION_BUFFER_SIZE(label_length) ((label_length) +4)

namespace 
{
	const char str_SMK[] = "SMK";
	const char str_SK[] = "SK";
	const char str_MK[] = "MK";
	const char str_VK[] = "VK";
}

// Derive key from shared key and key id.
// key id should be sample_derive_key_type_t.
bool derive_key(const sgx_ec256_dh_shared_t *p_shared_key, uint8_t key_id, sgx_ec_key_128bit_t* derived_key)
{
	sgx_status_t sample_ret = SGX_SUCCESS;
	sgx_cmac_128bit_key_t cmac_key;
	sgx_ec_key_128bit_t key_derive_key;

	std::memset(&cmac_key, 0, sizeof(cmac_key));

	sample_ret = sgx_rijndael128_cmac_msg(&cmac_key, (uint8_t*)p_shared_key, sizeof(sgx_ec256_dh_shared_t), (sgx_cmac_128bit_tag_t *)&key_derive_key);
	if (sample_ret != SGX_SUCCESS)
	{
		// memset here can be optimized away by compiler, so please use memset_s on
		// windows for production code and similar functions on other OSes.
		std::memset(&key_derive_key, 0, sizeof(key_derive_key));
		return false;
	}

	const char *label = NULL;
	uint32_t label_length = 0;
	switch (key_id)
	{
	case SAMPLE_DERIVE_KEY_SMK:
		label = str_SMK;
		label_length = sizeof(str_SMK) - 1;
		break;
	case SAMPLE_DERIVE_KEY_SK:
		label = str_SK;
		label_length = sizeof(str_SK) - 1;
		break;
	case SAMPLE_DERIVE_KEY_MK:
		label = str_MK;
		label_length = sizeof(str_MK) - 1;
		break;
	case SAMPLE_DERIVE_KEY_VK:
		label = str_VK;
		label_length = sizeof(str_VK) - 1;
		break;
	default:
		// memset here can be optimized away by compiler, so please use memset_s on
		// windows for production code and similar functions on other OSes.
		std::memset(&key_derive_key, 0, sizeof(key_derive_key));
		return false;
		break;
	}
	/* derivation_buffer = counter(0x01) || label || 0x00 || output_key_len(0x0080) */
	uint32_t derivation_buffer_length = EC_DERIVATION_BUFFER_SIZE(label_length);
	uint8_t *p_derivation_buffer = (uint8_t *)std::malloc(derivation_buffer_length);
	if (p_derivation_buffer == NULL)
	{
		// memset here can be optimized away by compiler, so please use memset_s on
		// windows for production code and similar functions on other OSes.
		std::memset(&key_derive_key, 0, sizeof(key_derive_key));
		return false;
	}
	std::memset(p_derivation_buffer, 0, derivation_buffer_length);

	/*counter = 0x01 */
	p_derivation_buffer[0] = 0x01;
	/*label*/
	std::memcpy(&p_derivation_buffer[1], label, derivation_buffer_length - 1);//label_length);
																		 /*output_key_len=0x0080*/
	uint16_t *key_len = (uint16_t *)(&(p_derivation_buffer[derivation_buffer_length - 2]));
	*key_len = 0x0080;


	sample_ret = sgx_rijndael128_cmac_msg((sgx_cmac_128bit_key_t *)&key_derive_key, p_derivation_buffer, derivation_buffer_length, (sgx_cmac_128bit_tag_t *)derived_key);
	std::free(p_derivation_buffer);
	// memset here can be optimized away by compiler, so please use memset_s on
	// windows for production code and similar functions on other OSes.
	std::memset(&key_derive_key, 0, sizeof(key_derive_key));
	if (sample_ret != SGX_SUCCESS)
	{
		return false;
	}
	return true;
}