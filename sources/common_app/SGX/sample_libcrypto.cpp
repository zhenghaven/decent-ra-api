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
#include "../../common/SGX/SGXOpenSSLConversions.h"

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
