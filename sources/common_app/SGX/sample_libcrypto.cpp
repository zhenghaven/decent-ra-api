#include <sgx_tcrypto.h>

#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <map>
#include <vector>

#include <cerrno>

#include <openssl/cmac.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/ecdsa.h>

#include "../Common.h"
#include "../../common/sgx_crypto_tools.h"

#include "SGXOpenSSLConversions.h"

namespace
{
	static std::map<void*, SHA256_CTX*> g_sha256StateMap; /* Probably this is useless, but keep it for now. */
	static const EC_GROUP* g_curve = EC_GROUP_new_by_curve_name(SGX_ECC256_CURVE_NAME);
}

sgx_status_t sgx_sha256_msg(const uint8_t *p_src, uint32_t src_len, sgx_sha256_hash_t *p_hash)
{
	if (!p_src || !src_len || !p_hash)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	SHA256(p_src, src_len, *p_hash);

	return SGX_SUCCESS;
}

sgx_status_t sgx_sha256_init(sgx_sha_state_handle_t* p_sha_handle)
{
	if (!p_sha_handle)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	SHA256_CTX* addr = new SHA256_CTX;
	g_sha256StateMap[addr] = addr;
	*p_sha_handle = addr;

	SHA256_Init(addr);

	return SGX_SUCCESS;
}

sgx_status_t sgx_sha256_update(const uint8_t *p_src, uint32_t src_len, sgx_sha_state_handle_t sha_handle)
{
	if (!sha_handle || !p_src || !src_len)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	SHA256_Update(reinterpret_cast<SHA256_CTX*>(sha_handle), p_src, src_len);

	return SGX_SUCCESS;
}

sgx_status_t sgx_sha256_get_hash(sgx_sha_state_handle_t sha_handle, sgx_sha256_hash_t *p_hash)
{
	if (!sha_handle || !p_hash)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	SHA256_CTX tmp;
	std::memcpy(&tmp, sha_handle, sizeof(SHA256_CTX));
	SHA256_Final(*p_hash, &tmp);

	return SGX_SUCCESS;
}

sgx_status_t sgx_sha256_close(sgx_sha_state_handle_t sha_handle)
{
	if (!sha_handle)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	auto it = g_sha256StateMap.find(sha_handle);
	if (it == g_sha256StateMap.end())
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	SHA256_CTX* addr = reinterpret_cast<SHA256_CTX*>(sha_handle);

	sgx_sha256_hash_t hash;
	SHA256_Final(hash, addr);

	delete addr;

	g_sha256StateMap.erase(it);

	return SGX_SUCCESS;
}

sgx_status_t sgx_rijndael128GCM_encrypt(const sgx_aes_gcm_128bit_key_t *p_key,
	const uint8_t *p_src,
	uint32_t src_len,
	uint8_t *p_dst,
	const uint8_t *p_iv,
	uint32_t iv_len,
	const uint8_t *p_aad,
	uint32_t aad_len,
	sgx_aes_gcm_128bit_tag_t *p_out_mac)
{
#pragma message("!!!!!!!!!TODO: Complete this function later.!!!!!!!!!!!")

	return SGX_SUCCESS;
}

sgx_status_t sgx_rijndael128GCM_decrypt(const sgx_aes_gcm_128bit_key_t *p_key,
	const uint8_t *p_src,
	uint32_t src_len,
	uint8_t *p_dst,
	const uint8_t *p_iv,
	uint32_t iv_len,
	const uint8_t *p_aad,
	uint32_t aad_len,
	const sgx_aes_gcm_128bit_tag_t *p_in_mac)
{
#pragma message("!!!!!!!!!TODO: Complete this function later.!!!!!!!!!!!")

	return SGX_SUCCESS;
}

sgx_status_t sgx_rijndael128_cmac_msg(const sgx_cmac_128bit_key_t *p_key, const uint8_t *p_src, uint32_t src_len, sgx_cmac_128bit_tag_t *p_mac)
{
	if (!p_key || !p_src || !src_len || !p_mac)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	size_t outCmacLen = 0;
	CMAC_CTX *ctx = CMAC_CTX_new();
	CMAC_Init(ctx, p_key, SGX_CMAC_KEY_SIZE, EVP_aes_128_cbc(), NULL);

	CMAC_Update(ctx, p_src, src_len);
	CMAC_Final(ctx, *p_mac, &outCmacLen);

	CMAC_CTX_free(ctx);

	if (outCmacLen != SGX_CMAC_MAC_SIZE)
	{
		LOGW("CMAC Tag size doesn't match! It should be %d, but the actual size is %llu.", SGX_CMAC_MAC_SIZE, outCmacLen);
		return SGX_ERROR_UNEXPECTED;
	}

	return SGX_SUCCESS;
}

//sgx_status_t sgx_cmac128_init(const sgx_cmac_128bit_key_t *p_key, sgx_cmac_state_handle_t* p_cmac_handle);
//sgx_status_t sgx_cmac128_update(const uint8_t *p_src, uint32_t src_len, sgx_cmac_state_handle_t cmac_handle);
//sgx_status_t sgx_cmac128_final(sgx_cmac_state_handle_t cmac_handle, sgx_cmac_128bit_tag_t *p_hash);
//sgx_status_t sgx_cmac128_close(sgx_cmac_state_handle_t cmac_handle);
//
//sgx_status_t sgx_aes_ctr_encrypt(
//	const sgx_aes_ctr_128bit_key_t *p_key,
//	const uint8_t *p_src,
//	const uint32_t src_len,
//	uint8_t *p_ctr,
//	const uint32_t ctr_inc_bits,
//	uint8_t *p_dst);
//
//sgx_status_t sgx_aes_ctr_decrypt(
//	const sgx_aes_ctr_128bit_key_t *p_key,
//	const uint8_t *p_src,
//	const uint32_t src_len,
//	uint8_t *p_ctr,
//	const uint32_t ctr_inc_bits,
//	uint8_t *p_dst);

sgx_status_t sgx_ecc256_open_context(sgx_ecc_state_handle_t* p_ecc_handle)
{
	return ECKeyOpenContext(p_ecc_handle) ? SGX_SUCCESS : SGX_ERROR_UNEXPECTED;
}

sgx_status_t sgx_ecc256_close_context(sgx_ecc_state_handle_t ecc_handle)
{
	ECKeyCloseContext(ecc_handle);
	return SGX_SUCCESS;
}

//sgx_status_t sgx_ecc256_check_point(const sgx_ec256_public_t *p_point, const sgx_ecc_state_handle_t ecc_handle, int *p_valid)
//{
//#pragma message("!!!!!!!!!TODO: Complete this function later.!!!!!!!!!!!")
//	
//	return SGX_SUCCESS;
//}

sgx_status_t sgx_ecc256_create_key_pair(sgx_ec256_private_t *p_private, sgx_ec256_public_t *p_public, sgx_ecc_state_handle_t ecc_handle)
{
	EC_KEY *key = nullptr;
	int opensslRes = 0;
	
	key = EC_KEY_new_by_curve_name(SGX_ECC256_CURVE_NAME);
	if (key == nullptr)
	{
		return SGX_ERROR_UNEXPECTED;
	}
	opensslRes = EC_KEY_generate_key(key);
	if (opensslRes != 1)
	{
		return SGX_ERROR_UNEXPECTED;
	}
	if (!ECKeyPairOpenSSL2SGX(key, p_private, p_public, ecc_handle))
	{
		return SGX_ERROR_UNEXPECTED;
	}

	return SGX_SUCCESS;
}

sgx_status_t sgx_ecc256_compute_shared_dhkey(sgx_ec256_private_t *p_private_b, sgx_ec256_public_t *p_public_ga, sgx_ec256_dh_shared_t *p_shared_key, sgx_ecc_state_handle_t ecc_handle)
{
	EVP_PKEY* myKey = EVP_PKEY_new();
	EVP_PKEY* peerKey = EVP_PKEY_new();
	EC_KEY* myECKey = EC_KEY_new();
	EC_KEY* peerECKey = EC_KEY_new();
	if (!myKey || !peerKey || !myECKey || !peerECKey)
	{
		EVP_PKEY_free(myKey);
		EVP_PKEY_free(peerKey);
		EC_KEY_free(myECKey);
		EC_KEY_free(peerECKey);
		return SGX_ERROR_UNEXPECTED;
	}

	if (!ECKeyPairSGX2OpenSSL(p_private_b, myECKey, ecc_handle))
	{
		EVP_PKEY_free(myKey);
		EVP_PKEY_free(peerKey);
		EC_KEY_free(myECKey);
		EC_KEY_free(peerECKey);
		return SGX_ERROR_UNEXPECTED;
	}

	if (!ECKeyPubSGX2OpenSSL(p_public_ga, peerECKey, ecc_handle))
	{
		EVP_PKEY_free(myKey);
		EVP_PKEY_free(peerKey);
		EC_KEY_free(myECKey);
		EC_KEY_free(peerECKey);
		return SGX_ERROR_UNEXPECTED;
	}

	int opensslRes = 0;

	opensslRes = EVP_PKEY_set1_EC_KEY(myKey, myECKey);
	if (opensslRes != 1)
	{
		EVP_PKEY_free(myKey);
		EVP_PKEY_free(peerKey);
		EC_KEY_free(myECKey);
		EC_KEY_free(peerECKey);
		return SGX_ERROR_UNEXPECTED;
	}
	opensslRes = EVP_PKEY_set1_EC_KEY(peerKey, peerECKey);
	if (opensslRes != 1)
	{
		EVP_PKEY_free(myKey);
		EVP_PKEY_free(peerKey);
		EC_KEY_free(myECKey);
		EC_KEY_free(peerECKey);
		return SGX_ERROR_UNEXPECTED;
	}
	
	if (!ECKeyCalcSharedKey(myKey, peerKey, p_shared_key))
	{
		EVP_PKEY_free(myKey);
		EVP_PKEY_free(peerKey);
		EC_KEY_free(myECKey);
		EC_KEY_free(peerECKey);
		return SGX_ERROR_UNEXPECTED;
	}

	EVP_PKEY_free(myKey);
	EVP_PKEY_free(peerKey);
	EC_KEY_free(myECKey);
	EC_KEY_free(peerECKey);
	return SGX_SUCCESS;
}

sgx_status_t sgx_ecdsa_sign(const uint8_t *p_data, uint32_t data_size, sgx_ec256_private_t *p_private, sgx_ec256_signature_t *p_signature, sgx_ecc_state_handle_t ecc_handle)
{
	sgx_sha256_hash_t hash;
	sgx_status_t sgxRes = sgx_sha256_msg(p_data, data_size, &hash);
	if (sgxRes != SGX_SUCCESS)
	{
		return sgxRes;
	}

	EC_KEY* prvECKey = EC_KEY_new();
	if (!prvECKey)
	{
		return SGX_ERROR_UNEXPECTED;
	}

	if (!ECKeyPairSGX2OpenSSL(p_private, prvECKey, ecc_handle))
	{
		EC_KEY_free(prvECKey);
		return SGX_ERROR_UNEXPECTED;
	}

	ECDSA_SIG* sign = ECDSA_do_sign(hash, SGX_SHA256_HASH_SIZE, prvECKey);
	if (!sign)
	{
		EC_KEY_free(prvECKey);
		return SGX_ERROR_UNEXPECTED;
	}

	if (!ECKeySignOpenSSL2SGX(sign, p_signature))
	{
		EC_KEY_free(prvECKey);
		ECDSA_SIG_free(sign);
		return SGX_ERROR_UNEXPECTED;
	}

	EC_KEY_free(prvECKey);
	ECDSA_SIG_free(sign);
	return SGX_SUCCESS;
}

sgx_status_t sgx_ecdsa_verify(const uint8_t *p_data, uint32_t data_size, const sgx_ec256_public_t *p_public, sgx_ec256_signature_t *p_signature, uint8_t *p_result, sgx_ecc_state_handle_t ecc_handle)
{
	sgx_sha256_hash_t hash;
	sgx_status_t sgxRes = sgx_sha256_msg(p_data, data_size, &hash);
	if (sgxRes != SGX_SUCCESS)
	{
		return sgxRes;
	}

	EC_KEY* pubECKey = EC_KEY_new();
	ECDSA_SIG* sign = ECDSA_SIG_new();
	if (!pubECKey || !sign)
	{
		EC_KEY_free(pubECKey);
		ECDSA_SIG_free(sign);
		return SGX_ERROR_UNEXPECTED;
	}

	if(!ECKeySignSGX2OpenSSL(p_signature, sign))
	{
		EC_KEY_free(pubECKey);
		ECDSA_SIG_free(sign);
		return SGX_ERROR_UNEXPECTED;
	}

	if (!ECKeyPubSGX2OpenSSL(p_public, pubECKey, ecc_handle))
	{
		EC_KEY_free(pubECKey);
		ECDSA_SIG_free(sign);
		return SGX_ERROR_UNEXPECTED;
	}

	int opensslRes = 0;
	
	opensslRes = ECDSA_do_verify(hash, SGX_SHA256_HASH_SIZE, sign, pubECKey);
	if (opensslRes == 1)
	{
		*p_result = SGX_EC_VALID;
	}
	else if (opensslRes == 0)
	{
		*p_result = SGX_EC_INVALID_SIGNATURE;
	}
	else
	{
		EC_KEY_free(pubECKey);
		ECDSA_SIG_free(sign);
		return SGX_ERROR_UNEXPECTED;
	}

	EC_KEY_free(pubECKey);
	ECDSA_SIG_free(sign);
	return SGX_SUCCESS;
}

//Copied from SDK code.
int consttime_memequal(const void *b1, const void *b2, size_t len)
{
	const unsigned char *c1 = reinterpret_cast<const unsigned char *>(b1), *c2 = reinterpret_cast<const unsigned char *>(b2);
	unsigned int res = 0;

	while (len--)
		res |= *c1++ ^ *c2++;

	/*
	* Map 0 to 1 and [1, 256) to 0 using only constant-time
	* arithmetic.
	*
	* This is not simply `!res' because although many CPUs support
	* branchless conditional moves and many compilers will take
	* advantage of them, certain compilers generate branches on
	* certain CPUs for `!res'.
	*/
	return (1 & ((res - 1) >> 8));
}
