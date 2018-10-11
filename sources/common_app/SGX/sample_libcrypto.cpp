#include <sgx_tcrypto.h>
#include <sgx_trts.h>

#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <map>
#include <vector>
#include <random>
//#include <chrono>
#include <climits>

#include <cerrno>

#include <openssl/cmac.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/ecdsa.h>

#include "../Common.h"
#include "../../common/SGX/sgx_crypto_tools.h"
#include "../../common/SGX/SGXOpenSSLConversions.h"

#define SGX_SP_IV_SIZE 12

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
	if ((!p_key || !p_src || !src_len || !p_dst || !p_iv || !p_out_mac) ||
		(aad_len > 0 && p_aad == nullptr) ||
		(p_aad != nullptr && aad_len == 0) ||
		(iv_len != SGX_AESGCM_IV_SIZE))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	int opensslRes = 0;
	int len = 0, ciphertext_len = 0;

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (ctx == nullptr)
	{
		return SGX_ERROR_UNEXPECTED;
	}
	//The IV length is always 12 (SGX_AESGCM_IV_SIZE), thus, this part is unnecessary.
	//opensslRes = EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr);
	//if (opensslRes != 1)
	//{
	//	EVP_CIPHER_CTX_free(ctx);
	//	return SGX_ERROR_UNEXPECTED;
	//}

	//opensslRes = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, nullptr);
	//if (opensslRes != 1)
	//{
	//	EVP_CIPHER_CTX_free(ctx);
	//	return SGX_ERROR_UNEXPECTED;
	//}

	opensslRes = EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, *p_key, p_iv);
	if (opensslRes != 1)
	{
		EVP_CIPHER_CTX_free(ctx);
		return SGX_ERROR_UNEXPECTED;
	}

	if (p_aad)
	{
		opensslRes = EVP_EncryptUpdate(ctx, nullptr, &len, p_aad, aad_len);
		if (opensslRes != 1)
		{
			EVP_CIPHER_CTX_free(ctx);
			return SGX_ERROR_UNEXPECTED;
		}
	}

	opensslRes = EVP_EncryptUpdate(ctx, p_dst, &len, p_src, src_len);
	if (opensslRes != 1)
	{
		EVP_CIPHER_CTX_free(ctx);
		return SGX_ERROR_UNEXPECTED;
	}

	ciphertext_len = len;

	opensslRes = EVP_EncryptFinal_ex(ctx, p_dst + len, &len);
	if (opensslRes != 1)
	{
		EVP_CIPHER_CTX_free(ctx);
		return SGX_ERROR_UNEXPECTED;
	}
	ciphertext_len += len;

	opensslRes = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, SGX_AESGCM_MAC_SIZE, *p_out_mac);
	if (opensslRes != 1)
	{
		EVP_CIPHER_CTX_free(ctx);
		return SGX_ERROR_UNEXPECTED;
	}

	EVP_CIPHER_CTX_free(ctx);
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
	if ((!p_key || !p_src || !src_len || !p_dst || !p_iv || !p_in_mac) ||
		(aad_len > 0 && p_aad == nullptr) ||
		(p_aad != nullptr && aad_len == 0) ||
		(iv_len != SGX_AESGCM_IV_SIZE))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}
	int opensslRes = 0;
	int len = 0, plaintext_len = 0;

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (ctx == nullptr)
	{
		return SGX_ERROR_UNEXPECTED;
	}
	//The IV length is always 12 (SGX_AESGCM_IV_SIZE), thus, this part is unnecessary.
	//opensslRes = EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr);
	//if (opensslRes != 1)
	//{
	//	EVP_CIPHER_CTX_free(ctx);
	//	return SGX_ERROR_UNEXPECTED;
	//}

	//opensslRes = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, nullptr);
	//if (opensslRes != 1)
	//{
	//	EVP_CIPHER_CTX_free(ctx);
	//	return SGX_ERROR_UNEXPECTED;
	//}

	opensslRes = EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, *p_key, p_iv);
	if (opensslRes != 1)
	{
		EVP_CIPHER_CTX_free(ctx);
		return SGX_ERROR_UNEXPECTED;
	}

	if (p_aad)
	{
		opensslRes = EVP_DecryptUpdate(ctx, nullptr, &len, p_aad, aad_len);
		if (opensslRes != 1)
		{
			EVP_CIPHER_CTX_free(ctx);
			return SGX_ERROR_UNEXPECTED;
		}
	}

	opensslRes = EVP_DecryptUpdate(ctx, p_dst, &len, p_src, src_len);
	if (opensslRes != 1)
	{
		EVP_CIPHER_CTX_free(ctx);
		return SGX_ERROR_UNEXPECTED;
	}

	plaintext_len = len;

	opensslRes = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, SGX_AESGCM_MAC_SIZE, const_cast<uint8_t*>(*p_in_mac));
	if (opensslRes != 1)
	{
		EVP_CIPHER_CTX_free(ctx);
		return SGX_ERROR_UNEXPECTED;
	}

	opensslRes = EVP_DecryptFinal_ex(ctx, p_dst + len, &len);
	plaintext_len += len;

	EVP_CIPHER_CTX_free(ctx);

	switch (opensslRes)
	{
	case 1:
		return SGX_SUCCESS;
		break;
	case 0:
		return SGX_ERROR_MAC_MISMATCH;
		break;
	default:
		return SGX_ERROR_UNEXPECTED;
		break;
	}
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
	if (!p_ecc_handle)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}
	return ECKeyOpenContext(p_ecc_handle) ? SGX_SUCCESS : SGX_ERROR_UNEXPECTED;
}

sgx_status_t sgx_ecc256_close_context(sgx_ecc_state_handle_t ecc_handle)
{
	ECKeyCloseContext(ecc_handle);
	return SGX_SUCCESS;
}

sgx_status_t sgx_ecdsa_sign(const uint8_t *p_data, uint32_t data_size, sgx_ec256_private_t *p_private, sgx_ec256_signature_t *p_signature, sgx_ecc_state_handle_t ecc_handle)
{
	if (!p_data || !data_size || !p_private || !p_signature || !ecc_handle)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	sgx_sha256_hash_t hash;
	sgx_status_t sgxRes = sgx_sha256_msg(p_data, data_size, &hash);
	if (sgxRes != SGX_SUCCESS)
	{
		return sgxRes;
	}

	EC_KEY* prvECKey = ECKeyGeneral2OpenSSL(SgxEc256Type2General(p_private), nullptr, ecc_handle);
	if (!prvECKey)
	{
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
	if (!p_data || !data_size || !p_public || !p_signature || !p_result || !ecc_handle)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	sgx_sha256_hash_t hash;
	sgx_status_t sgxRes = sgx_sha256_msg(p_data, data_size, &hash);
	if (sgxRes != SGX_SUCCESS)
	{
		return sgxRes;
	}

	EC_KEY* pubECKey = ECKeyGeneral2OpenSSL(SgxEc256Type2General(p_public), ecc_handle);
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

	sgx_status_t ret = SGX_SUCCESS;
	
	switch (ECDSA_do_verify(hash, SGX_SHA256_HASH_SIZE, sign, pubECKey))
	{
	case 0:
		*p_result = SGX_EC_INVALID_SIGNATURE;
		break;
	case 1:
		*p_result = SGX_EC_VALID;
		break;
	default:
		ret = SGX_ERROR_UNEXPECTED;
		break;
	}

	EC_KEY_free(pubECKey);
	ECDSA_SIG_free(sign);
	
	return ret;
}
