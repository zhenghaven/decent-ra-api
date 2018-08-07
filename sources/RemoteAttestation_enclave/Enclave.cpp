#include <map>

#include <sgx_tcrypto.h>

//#include <cppcodec/base64_rfc4648.hpp>
//
//#include <rapidjson/rapidjson.h>
//#include <rapidjson/document.h>
//#include <rapidjson/stringbuffer.h>
//#include <rapidjson/writer.h>
//
//#include <openssl/ec.h>
//#include <openssl/obj_mac.h>
//#include <openssl/pem.h>

#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */

#include "../common_enclave/enclave_tools.h"
//#include "../common_enclave/RAConnection.h"
//#include "../common_enclave/RAKeyManager.h"
//#include "../common_enclave/DecentCryptoManager.h"
#include "../common_enclave/EnclaveStatus.h"

#include "../common/CryptoTools.h"
#include "../common/Decent.h"
#include "../common/sgx_constants.h"

//int EC_KEY_get_asn1_flag(const EC_KEY* key)
//{
//	if (key)
//	{
//		const EC_GROUP* group = EC_KEY_get0_group(key);
//		if (group)
//		{
//			return EC_GROUP_get_asn1_flag(group);
//		}
//		return 0;
//	}
//}


sgx_status_t ecall_get_ra_pub_enc_key(sgx_ra_context_t context, sgx_ec256_public_t* outKey)
{
	sgx_status_t res = SGX_SUCCESS;
	if (EnclaveState::GetInstance().GetCryptoMgr().GetStatus() != SGX_SUCCESS)
	{
		return EnclaveState::GetInstance().GetCryptoMgr().GetStatus();
	}

	std::memcpy(outKey, &(EnclaveState::GetInstance().GetCryptoMgr().GetEncrPubKey()), sizeof(sgx_ec256_public_t));
	return res;
}

sgx_status_t ecall_get_ra_pub_sig_key(sgx_ra_context_t context, sgx_ec256_public_t* outKey)
{
	sgx_status_t res = SGX_SUCCESS;
	if (EnclaveState::GetInstance().GetCryptoMgr().GetStatus() != SGX_SUCCESS)
	{
		return EnclaveState::GetInstance().GetCryptoMgr().GetStatus();
	}

	std::memcpy(outKey, &(EnclaveState::GetInstance().GetCryptoMgr().GetSignPubKey()), sizeof(sgx_ec256_public_t));
	return res;
}

void ecall_termination_clean()
{
	EnclaveState::GetInstance().Clear();
}

//void GenSSLECKeys()
//{
//	EC_KEY *key = nullptr; 
//	EVP_PKEY *pkey = NULL;
//	int eccgrp;
//	int res = 0;
//
//	key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
//	if (!key)
//	{
//		enclave_printf("Gen key failed. - 0\n");
//	}
//
//	EC_KEY_set_asn1_flag(key, OPENSSL_EC_NAMED_CURVE);
//
//	res = EC_KEY_generate_key(key);
//	if (!res)
//	{
//		enclave_printf("Gen key failed. - 1\n");
//	}
//
//	pkey = EVP_PKEY_new();
//
//	res = EVP_PKEY_assign_EC_KEY(pkey, key);
//	if (!res)
//	{
//		enclave_printf("Gen key failed. - 2\n");
//	}
//
//
//	//BIGNUM *prv = nullptr;
//	//EC_POINT *pub = nullptr;
//
//	//EC_KEY_set_private_key(key, prv);
//	//EC_KEY_set_public_key(key, pub);
//}

sgx_status_t ecall_get_simple_secret(const char* clientID, uint64_t* secret, sgx_aes_gcm_128bit_tag_t* outSecretMac)
{
	sgx_status_t enclaveRes = SGX_SUCCESS;

	static uint64_t simple_secret = 1234567;

	//if (ecall_get_decent_mode() != DecentNodeMode::APPL_SERVER)
	//{
	//	return SGX_ERROR_UNEXPECTED;
	//}
	//if (!IsBothWayAttested(clientID))
	//{
	//	return SGX_ERROR_UNEXPECTED;
	//}

	auto it = EnclaveState::GetInstance().GetServersMap().find(clientID);

	RAKeyManager& serverKeyMgr = it->second.second;

	uint8_t aes_gcm_iv[SAMPLE_SP_IV_SIZE] = { 0 };
	enclaveRes = sgx_rijndael128GCM_encrypt(&serverKeyMgr.GetSK(),
		reinterpret_cast<const uint8_t*>(&simple_secret),
		sizeof(uint64_t),
		reinterpret_cast<uint8_t*>(secret),
		aes_gcm_iv,
		SAMPLE_SP_IV_SIZE,
		nullptr,
		0,
		outSecretMac
	);

	enclave_printf("\n-Inside Enclave- Encrypted a simple secret: %llu\n\n", simple_secret);

	return enclaveRes;
}

sgx_status_t ecall_proc_simple_secret(const char* clientID, const uint64_t* secret, const sgx_aes_gcm_128bit_tag_t* inSecretMac)
{
	sgx_status_t enclaveRes = SGX_SUCCESS;

	//if (g_decentMode != DecentNodeMode::APPL_SERVER)
	//{
	//	return SGX_ERROR_UNEXPECTED;
	//}
	//if (!IsBothWayAttested(clientID))
	//{
	//	return SGX_ERROR_UNEXPECTED;
	//}

	auto it = EnclaveState::GetInstance().GetServersMap().find(clientID);

	RAKeyManager& serverKeyMgr = it->second.second;
	uint64_t simple_secret = 0;

	uint8_t aes_gcm_iv[SAMPLE_SP_IV_SIZE] = { 0 };
	enclaveRes = sgx_rijndael128GCM_decrypt(&serverKeyMgr.GetSK(),
		reinterpret_cast<const uint8_t*>(secret),
		sizeof(uint64_t),
		reinterpret_cast<uint8_t*>(&simple_secret),
		aes_gcm_iv,
		SAMPLE_SP_IV_SIZE,
		nullptr,
		0,
		inSecretMac
	);

	enclave_printf("\n-Inside Enclave- Decrypted a simple secret: %llu\n\n", simple_secret);

	return enclaveRes;
}

sgx_status_t ecall_crypto_test(sgx_ec256_public_t* peerKey, sgx_ec256_dh_shared_t* sharedKey)
{
	sgx_status_t enclaveRes = SGX_SUCCESS;
	enclaveRes = sgx_ecc256_compute_shared_dhkey(const_cast<sgx_ec256_private_t*>(&EnclaveState::GetInstance().GetCryptoMgr().GetEncrPriKey()), peerKey, sharedKey, EnclaveState::GetInstance().GetCryptoMgr().GetECC());
	return enclaveRes;
}
