#include <map>

#include <sgx_tcrypto.h>

#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */

#include "../common_enclave/Common.h"
#include "../common_enclave/DecentError.h"

#include "../common/DataCoding.h"
#include "../common/SGX/sgx_constants.h"

sgx_status_t ecall_get_simple_secret(const char* clientID, uint64_t* secret, sgx_aes_gcm_128bit_tag_t* outSecretMac)
{
	sgx_status_t enclaveRes = SGX_SUCCESS;

	static uint64_t simple_secret = 1234567;



	//uint8_t aes_gcm_iv[SGX_AESGCM_IV_SIZE] = { 0 };
	//enclaveRes = sgx_rijndael128GCM_encrypt(&nodeKeyMgr->GetSK(),
	//	reinterpret_cast<const uint8_t*>(&simple_secret),
	//	sizeof(uint64_t),
	//	reinterpret_cast<uint8_t*>(secret),
	//	aes_gcm_iv,
	//	SGX_AESGCM_IV_SIZE,
	//	nullptr,
	//	0,
	//	outSecretMac
	//);

	ocall_printf("\n-Inside Enclave- Encrypted a simple secret: %llu\n\n", simple_secret);

	return enclaveRes;
}

sgx_status_t ecall_proc_simple_secret(const char* clientID, const uint64_t* secret, const sgx_aes_gcm_128bit_tag_t* inSecretMac)
{
	sgx_status_t enclaveRes = SGX_SUCCESS;


	uint64_t simple_secret = 0;

	//uint8_t aes_gcm_iv[SGX_AESGCM_IV_SIZE] = { 0 };
	//enclaveRes = sgx_rijndael128GCM_decrypt(&nodeKeyMgr->GetSK(),
	//	reinterpret_cast<const uint8_t*>(secret),
	//	sizeof(uint64_t),
	//	reinterpret_cast<uint8_t*>(&simple_secret),
	//	aes_gcm_iv,
	//	SGX_AESGCM_IV_SIZE,
	//	nullptr,
	//	0,
	//	inSecretMac
	//);

	ocall_printf("\n-Inside Enclave- Decrypted a simple secret: %llu\n\n", simple_secret);

	return enclaveRes;
}

sgx_status_t ecall_crypto_test(const sgx_aes_gcm_128bit_key_t *p_key, const uint8_t *p_src, uint32_t src_len, uint8_t *p_dst, const uint8_t *p_iv, uint32_t iv_len, const uint8_t *p_aad, uint32_t aad_len, const sgx_aes_gcm_128bit_tag_t *p_out_mac)
{
	sgx_status_t enclaveRes = SGX_SUCCESS;
	uint8_t res = 0;
	uint8_t aes_gcm_iv[SGX_AESGCM_IV_SIZE] = { 0 };
	enclaveRes = sgx_rijndael128GCM_decrypt(p_key, p_src, src_len, p_dst, aes_gcm_iv, SGX_AESGCM_IV_SIZE, nullptr, 0, p_out_mac);
	return enclaveRes;
}
