#include <sgx_tcrypto.h>

#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <map>

#include <cerrno>

#include <openssl/cmac.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/evp.h>

#include "../Common.h"
#include "../../common/sgx_crypto_tools.h"

#define SGX_ECC256_CURVE_NAME NID_X9_62_prime256v1

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

sgx_status_t sgx_rijndael128_cmac_msg(const sgx_cmac_128bit_key_t *p_key, const uint8_t *p_src, uint32_t src_len, sgx_cmac_128bit_tag_t *p_mac)
{
//#pragma message("!!!!!!!!!TODO: Complete this function later.!!!!!!!!!!!")

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

sgx_status_t sgx_ecc256_open_context(sgx_ecc_state_handle_t* p_ecc_handle)
{
	#pragma message("!!!!!!!!!TODO: Complete this function later.!!!!!!!!!!!")

	return SGX_SUCCESS;
}

sgx_status_t sgx_ecc256_close_context(sgx_ecc_state_handle_t ecc_handle)
{
	#pragma message("!!!!!!!!!TODO: Complete this function later.!!!!!!!!!!!")

	return SGX_SUCCESS;
}

//sgx_status_t sgx_ecc256_check_point(const sgx_ec256_public_t *p_point, const sgx_ecc_state_handle_t ecc_handle, int *p_valid)
//{
//#pragma message("!!!!!!!!!TODO: Complete this function later.!!!!!!!!!!!")
//	
//	return SGX_SUCCESS;
//}

bool ECKeyPrvOpenSSL2SGX(const BIGNUM *inPrv, sgx_ec256_private_t *outPrv)
{
	if (!inPrv || !outPrv)
	{
		return false;
	}

	int prvSize = BN_num_bytes(inPrv);
	if (prvSize != SGX_ECP256_KEY_SIZE)
	{
		return false;
	}
	BN_bn2bin(inPrv, outPrv->r);

	return true;
}

bool ECKeyPubOpenSSL2SGX(const EC_POINT *inPub, sgx_ec256_public_t *outPub)
{
	if (!inPub || !outPub)
	{
		return false;
	}

	int opensslRes = 0;

	EC_GROUP* curve = EC_GROUP_new_by_curve_name(SGX_ECC256_CURVE_NAME);
	if (curve == nullptr)
	{
		return false;
	}

	BN_CTX* pubCtx = BN_CTX_new();
	BIGNUM* pubX = BN_new();
	BIGNUM* pubY = BN_new();
	if (!pubCtx || !pubX || !pubY)
	{
		BN_free(pubX);
		BN_free(pubY);
		BN_CTX_free(pubCtx);
		EC_GROUP_free(curve);
		return false;
	}

	opensslRes = EC_POINT_get_affine_coordinates_GFp(curve, inPub, pubX, pubY, pubCtx);
	if (opensslRes != 1)
	{
		BN_free(pubX);
		BN_free(pubY);
		BN_CTX_free(pubCtx);
		EC_GROUP_free(curve);
		return false;;
	}
	int pubSize = 0;
	pubSize = BN_num_bytes(pubX);
	if (pubSize != SGX_ECP256_KEY_SIZE)
	{
		BN_free(pubX);
		BN_free(pubY);
		BN_CTX_free(pubCtx);
		EC_GROUP_free(curve);
		return false;
	}
	pubSize = BN_num_bytes(pubY);
	if (pubSize != SGX_ECP256_KEY_SIZE)
	{
		BN_free(pubX);
		BN_free(pubY);
		BN_CTX_free(pubCtx);
		EC_GROUP_free(curve);
		return false;
	}

	BN_bn2bin(pubX, outPub->gx);
	BN_bn2bin(pubY, outPub->gy);

	BN_free(pubX);
	BN_free(pubY);
	BN_CTX_free(pubCtx);
	EC_GROUP_free(curve);

	return true;
}

bool ECKeyPairOpenSSL2SGX(const EC_KEY *inKeyPair, sgx_ec256_private_t *outPrv, sgx_ec256_public_t *outPub)
{
	if (!inKeyPair || !outPrv || !outPub)
	{
		return false;
	}

	const BIGNUM *prv = EC_KEY_get0_private_key(inKeyPair);
	if (prv == nullptr)
	{
		return false;
	}

	const EC_POINT *pub = EC_KEY_get0_public_key(inKeyPair);
	if (pub == nullptr)
	{
		return false;
	}

	if (!ECKeyPrvOpenSSL2SGX(prv, outPrv))
	{
		return false;
	}
	if (!ECKeyPubOpenSSL2SGX(pub, outPub))
	{
		return false;
	}

	return true;
}

bool ECKeyPrvSGX2OpenSSL(const sgx_ec256_private_t *inPrv, BIGNUM *outPrv)
{
	if (!inPrv || !outPrv)
	{
		return false;
	}

	BN_bin2bn(inPrv->r, SGX_ECP256_KEY_SIZE, outPrv);

	return true;
}

bool ECKeyPubSGX2OpenSSL(const sgx_ec256_public_t *inPub, EC_POINT *outPub)
{
	if (!g_curve || !inPub || !outPub)
	{
		return false;
	}

	int opensslRes = 0;

	BN_CTX* pubCtx = BN_CTX_new();
	BIGNUM* pubX = BN_new();
	BIGNUM* pubY = BN_new();
	if (!pubCtx || !pubX || !pubY)
	{
		BN_free(pubX);
		BN_free(pubY);
		BN_CTX_free(pubCtx);
		return false;
	}

	BN_bin2bn(inPub->gx, SGX_ECP256_KEY_SIZE, pubX);
	BN_bin2bn(inPub->gy, SGX_ECP256_KEY_SIZE, pubY);

	opensslRes = EC_POINT_set_affine_coordinates_GFp(g_curve, outPub, pubX, pubY, pubCtx);
	if (opensslRes != 1)
	{
		BN_free(pubX);
		BN_free(pubY);
		BN_CTX_free(pubCtx);
		return false;
	}

	BN_free(pubX);
	BN_free(pubY);
	BN_CTX_free(pubCtx);

	return true;
}

bool ECKeyPairSGX2OpenSSL(const sgx_ec256_private_t *inPrv, const sgx_ec256_public_t *inPub, EC_KEY *outKeyPair)
{
	int opensslRes = 0;

	if (!g_curve || !inPrv || !inPub || !outKeyPair)
	{
		return false;
	}

	opensslRes = EC_KEY_set_group(outKeyPair, g_curve);
	if (opensslRes != 1)
	{
		return false;
	}

	BIGNUM* prvR = BN_new();
	EC_POINT* pub = EC_POINT_new(g_curve);
	if (!prvR || !pub)
	{
		BN_free(prvR);
		EC_POINT_free(pub);
		return false;
	}

	if (!ECKeyPrvSGX2OpenSSL(inPrv, prvR))
	{
		BN_free(prvR);
		EC_POINT_free(pub);
		return false;
	}
	if (!ECKeyPubSGX2OpenSSL(inPub, pub))
	{
		BN_free(prvR);
		EC_POINT_free(pub);
		return false;
	}
	opensslRes = EC_KEY_set_private_key(outKeyPair, prvR);
	if (opensslRes != 1)
	{
		BN_free(prvR);
		EC_POINT_free(pub);
		return false;
	}
	opensslRes = EC_KEY_set_public_key(outKeyPair, pub);
	if (opensslRes != 1)
	{
		BN_free(prvR);
		EC_POINT_free(pub);
		return false;
	}

	BN_free(prvR);
	EC_POINT_free(pub);
	return true;
}

bool ECKeyGetPubFromPrv(const BIGNUM* inPrv, EC_POINT* outPub)
{
	if (!g_curve || !inPrv || !outPub)
	{
		return false;
	}

	BN_CTX* pubCtx = BN_CTX_new();
	if (!pubCtx)
	{
		return false;
	}

	int opensslRes = 0;

	opensslRes = EC_POINT_mul(g_curve, outPub, inPrv, NULL, NULL, pubCtx);

	if (opensslRes != 1)
	{
		BN_CTX_free(pubCtx);
		return false;
	}

	BN_CTX_free(pubCtx);
	return true;
}

bool ECKeyPairSGX2OpenSSL(const sgx_ec256_private_t *inPrv, EC_KEY *outKeyPair)
{
	if (!g_curve || !inPrv || !outKeyPair)
	{
		return false;
	}

	int opensslRes = 0;

	opensslRes = EC_KEY_set_group(outKeyPair, g_curve);
	if (opensslRes != 1)
	{
		return false;
	}

	BIGNUM* prvR = BN_new();
	EC_POINT* pub = EC_POINT_new(g_curve);
	if (!prvR || !pub)
	{
		BN_free(prvR);
		EC_POINT_free(pub);
		return false;
	}

	if (!ECKeyPrvSGX2OpenSSL(inPrv, prvR))
	{
		BN_free(prvR);
		EC_POINT_free(pub);
		return false;
	}

	if (!ECKeyGetPubFromPrv(prvR, pub))
	{
		BN_free(prvR);
		EC_POINT_free(pub);
		return false;
	}

	opensslRes = EC_KEY_set_private_key(outKeyPair, prvR);
	if (opensslRes != 1)
	{
		BN_free(prvR);
		EC_POINT_free(pub);
		return false;
	}
	opensslRes = EC_KEY_set_public_key(outKeyPair, pub);
	if (opensslRes != 1)
	{
		BN_free(prvR);
		EC_POINT_free(pub);
		return false;
	}

	BN_free(prvR);
	EC_POINT_free(pub);
	return true;
}

bool ECKeyPubSGX2OpenSSL(const sgx_ec256_public_t *inPub, EC_KEY *outKeyPair)
{
	int opensslRes = 0;

	if (!g_curve || !inPub || !outKeyPair)
	{
		return false;
	}

	opensslRes = EC_KEY_set_group(outKeyPair, g_curve);
	if (opensslRes != 1)
	{
		return false;
	}

	EC_POINT* pub = EC_POINT_new(g_curve);
	if (!pub)
	{
		EC_POINT_free(pub);
		return false;
	}

	if (!ECKeyPubSGX2OpenSSL(inPub, pub))
	{
		EC_POINT_free(pub);
		return false;
	}

	opensslRes = EC_KEY_set_public_key(outKeyPair, pub);
	if (opensslRes != 1)
	{
		EC_POINT_free(pub);
		return false;
	}

	EC_POINT_free(pub);
	return true;
}

bool ECKeyCalcSharedKey(EVP_PKEY* inKey, EVP_PKEY* inPeerKey, sgx_ec256_dh_shared_t *outSharedkey)
{
	if (!inKey || !inPeerKey)
	{
		return false;
	}

	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(inKey, nullptr);
	if (!ctx)
	{
		return false;
	}

	if (EVP_PKEY_derive_init(ctx) <= 0)
	{
		EVP_PKEY_CTX_free(ctx);
		return false;
	}

	if (EVP_PKEY_derive_set_peer(ctx, inPeerKey) <= 0)
	{
		EVP_PKEY_CTX_free(ctx);
		return false;
	}

	size_t keySize = 0;
	if (EVP_PKEY_derive(ctx, NULL, &keySize) <= 0)
	{
		EVP_PKEY_CTX_free(ctx);
		return false;
	}

	if (keySize != SGX_ECP256_KEY_SIZE)
	{
		EVP_PKEY_CTX_free(ctx);
		return false;
	}

	if (EVP_PKEY_derive(ctx, outSharedkey->s, &keySize) <= 0)
	{
		EVP_PKEY_CTX_free(ctx);
		return false;
	}

	EVP_PKEY_CTX_free(ctx);
	return true;
}

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
	if (!ECKeyPairOpenSSL2SGX(key, p_private, p_public))
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

	if (!ECKeyPairSGX2OpenSSL(p_private_b, myECKey))
	{
		EVP_PKEY_free(myKey);
		EVP_PKEY_free(peerKey);
		EC_KEY_free(myECKey);
		EC_KEY_free(peerECKey);
		return SGX_ERROR_UNEXPECTED;
	}

	if (!ECKeyPubSGX2OpenSSL(p_public_ga, peerECKey))
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
	#pragma message("!!!!!!!!!TODO: Complete this function later.!!!!!!!!!!!")

	return SGX_SUCCESS;
}

//sgx_status_t sgx_ecdsa_verify(const uint8_t *p_data, uint32_t data_size, const sgx_ec256_public_t *p_public, sgx_ec256_signature_t *p_signature, uint8_t *p_result, sgx_ecc_state_handle_t ecc_handle)
//{
//#pragma message("!!!!!!!!!TODO: Complete this function later.!!!!!!!!!!!")
//
//	return SGX_SUCCESS;
//}

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
