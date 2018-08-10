#include "sgx_crypto_tools.h"

#include <cstring>
#include <cstdlib>

#include <sgx_error.h>
#include <sgx_tcrypto.h>

#define EC_DERIVATION_BUFFER_SIZE(label_length) ((label_length) +4)

sgx_status_t sp_derive_key(const sgx_ec256_dh_shared_t* shared_key, const char* label, uint32_t label_length, sgx_ec_key_128bit_t* derived_key)
{
	sgx_status_t se_ret = SGX_SUCCESS;
	sgx_cmac_128bit_key_t cmac_key;
	sgx_ec_key_128bit_t key_derive_key;
	if (!shared_key || !derived_key || !label)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	/*check integer overflow */
	if (label_length > EC_DERIVATION_BUFFER_SIZE(label_length))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	std::memset(&cmac_key, 0, sizeof(cmac_key));

	se_ret = sgx_rijndael128_cmac_msg(&cmac_key, (uint8_t*)shared_key, sizeof(sgx_ec256_dh_shared_t), (sgx_cmac_128bit_tag_t *)&key_derive_key);
	if (SGX_SUCCESS != se_ret)
	{
		// TODO: memset here can be optimized away by compiler, so please use memset_s on
		// windows for production code and similar functions on other OSes.
		std::memset(&key_derive_key, 0, sizeof(key_derive_key));
		return se_ret;
	}
	/* derivation_buffer = counter(0x01) || label || 0x00 || output_key_len(0x0080) */
	uint32_t derivation_buffer_length = EC_DERIVATION_BUFFER_SIZE(label_length);
	uint8_t *p_derivation_buffer = (uint8_t *)malloc(derivation_buffer_length);
	if (p_derivation_buffer == NULL)
	{
		return SGX_ERROR_OUT_OF_MEMORY;
	}
	memset(p_derivation_buffer, 0, derivation_buffer_length);

	/*counter = 0x01 */
	p_derivation_buffer[0] = 0x01;
	/*label*/
	memcpy(&p_derivation_buffer[1], label, label_length);
	/*output_key_len=0x0080*/
	uint16_t *key_len = (uint16_t *)&p_derivation_buffer[derivation_buffer_length - 2];
	*key_len = 0x0080;

	se_ret = sgx_rijndael128_cmac_msg((sgx_cmac_128bit_key_t *)&key_derive_key, p_derivation_buffer, derivation_buffer_length, (sgx_cmac_128bit_tag_t *)derived_key);
	std::free(p_derivation_buffer);
	// memset here can be optimized away by compiler, so please use memset_s on
	// windows for production code and similar functions on other OSes.
	std::memset(&key_derive_key, 0, sizeof(key_derive_key));

	return se_ret;
}

sgx_status_t sp_derive_key_type(const sgx_ec256_dh_shared_t * shared_key, sgx_derive_key_type_t type, sgx_ec_key_128bit_t * derived_key)
{
	const char *label = NULL;
	uint32_t label_length = 0;
	switch (type)
	{
	case SGX_DERIVE_KEY_SMK:
		label = SGX_SMK_KEY_LABEL_STR;
		label_length = sizeof(SGX_SMK_KEY_LABEL_STR) - 1;
		break;
	case SGX_DERIVE_KEY_SK:
		label = SGX_SK_KEY_LABEL_STR;
		label_length = sizeof(SGX_SK_KEY_LABEL_STR) - 1;
		break;
	case SGX_DERIVE_KEY_MK:
		label = SGX_MK_KEY_LABEL_STR;
		label_length = sizeof(SGX_MK_KEY_LABEL_STR) - 1;
		break;
	case SGX_DERIVE_KEY_VK:
		label = SGX_VK_KEY_LABEL_STR;
		label_length = sizeof(SGX_VK_KEY_LABEL_STR) - 1;
		break;
	}

	return sp_derive_key(shared_key, label, label_length, derived_key);
}

sgx_status_t verify_cmac128(const sgx_ec_key_128bit_t* mac_key, const uint8_t* data_buf, uint32_t buf_size, const uint8_t* mac_buf)
{
	uint8_t data_mac[SGX_CMAC_MAC_SIZE];
	sgx_status_t se_ret = SGX_SUCCESS;

	if (!data_buf || !mac_buf || !mac_key)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	se_ret = sgx_rijndael128_cmac_msg((const sgx_cmac_128bit_key_t*)mac_key, data_buf, buf_size, (sgx_cmac_128bit_tag_t *)data_mac);
	if (SGX_SUCCESS != se_ret)
	{
		return se_ret;
	}
	if (consttime_memequal(mac_buf, data_mac, SGX_CMAC_MAC_SIZE) == 0)
	{
		return SGX_ERROR_MAC_MISMATCH;
	}

	return se_ret;
}
