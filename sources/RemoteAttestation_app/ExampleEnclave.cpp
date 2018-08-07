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

sgx_status_t ExampleEnclave::CryptoTest(const uint8_t *p_data, uint32_t data_size, const sgx_ec256_public_t *p_public, sgx_ec256_signature_t *p_signature)
{
	sgx_status_t res = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;

	res = ecall_crypto_test(GetEnclaveId(), &retval, p_data, data_size, p_public, p_signature);

	return res == SGX_SUCCESS ? retval : res;
}
