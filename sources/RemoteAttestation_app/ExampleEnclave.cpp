#include "ExampleEnclave.h"

#include "Enclave_u.h"

ExampleEnclave::~ExampleEnclave()
{
}

sgx_status_t ExampleEnclave::GetSimpleSecret(const std::string & id, uint64_t & secret, sgx_aes_gcm_128bit_tag_t & outSecretMac)
{
	sgx_status_t res = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;

	res = ecall_get_simple_secret(GetEnclaveId(), &retval, id.c_str(), &secret, &outSecretMac);

	return res == SGX_SUCCESS ? retval : res;
}

sgx_status_t ExampleEnclave::ProcessSimpleSecret(const std::string & id, const uint64_t & secret, const sgx_aes_gcm_128bit_tag_t & inSecretMac)
{
	sgx_status_t res = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;

	res = ecall_proc_simple_secret(GetEnclaveId(), &retval, id.c_str(), &secret, &inSecretMac);

	return res == SGX_SUCCESS ? retval : res;
}

sgx_status_t ExampleEnclave::CryptoTest(const sgx_aes_gcm_128bit_key_t *p_key, const uint8_t *p_src, uint32_t src_len, uint8_t *p_dst, const uint8_t *p_iv, uint32_t iv_len, const uint8_t *p_aad, uint32_t aad_len, sgx_aes_gcm_128bit_tag_t *p_out_mac)
{
	sgx_status_t res = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;

	res = ecall_crypto_test(GetEnclaveId(), &retval, p_key, p_src, src_len, p_dst, p_iv, iv_len, p_aad, aad_len, p_out_mac);

	return res == SGX_SUCCESS ? retval : res;
}
