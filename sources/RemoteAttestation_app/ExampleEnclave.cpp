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

sgx_status_t ExampleEnclave::CryptoTest(sgx_ec256_public_t* peerKey, sgx_ec256_dh_shared_t* sharedKey)
{
	sgx_status_t res = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;

	res = ecall_crypto_test(GetEnclaveId(), &retval, peerKey, sharedKey);

	return res == SGX_SUCCESS ? retval : res;
}
