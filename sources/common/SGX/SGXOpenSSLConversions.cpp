#include "SGXOpenSSLConversions.h"

#include <cstddef>

//#include <xutility>
#include <vector>
#include <cstdint>
#include <iterator>
#include <algorithm>

#include <openssl/cmac.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/evp.h>

#include <sgx_tcrypto.h>

#include "../OpenSSLTools.h"
#include "../OpenSSLConversions.h"

#define SGX_GENERAL_KEY_TYPE_ERROR_MSG "The key type of SGX is incompatible with the general key type!"

static_assert(SGX_ECC256_CURVE_NAME == ECC256_CURVE_NAME, SGX_GENERAL_KEY_TYPE_ERROR_MSG);

static_assert(sizeof(sgx_ec256_private_t) == sizeof(general_secp256r1_private_t), SGX_GENERAL_KEY_TYPE_ERROR_MSG);
static_assert(sizeof(sgx_ec256_public_t) == sizeof(general_secp256r1_public_t), SGX_GENERAL_KEY_TYPE_ERROR_MSG);
static_assert(sizeof(sgx_ec256_dh_shared_t) == sizeof(general_secp256r1_shared_t), SGX_GENERAL_KEY_TYPE_ERROR_MSG);
static_assert(sizeof(sgx_ec256_signature_t) == sizeof(general_secp256r1_signature_t), SGX_GENERAL_KEY_TYPE_ERROR_MSG);

static_assert(offsetof(sgx_ec256_private_t, r) == offsetof(general_secp256r1_private_t, r), SGX_GENERAL_KEY_TYPE_ERROR_MSG);

static_assert(offsetof(sgx_ec256_public_t, gx) == offsetof(general_secp256r1_public_t, x), SGX_GENERAL_KEY_TYPE_ERROR_MSG);
static_assert(offsetof(sgx_ec256_public_t, gy) == offsetof(general_secp256r1_public_t, y), SGX_GENERAL_KEY_TYPE_ERROR_MSG);

static_assert(offsetof(sgx_ec256_dh_shared_t, s) == offsetof(sgx_ec256_dh_shared_t, s), SGX_GENERAL_KEY_TYPE_ERROR_MSG);

static_assert(offsetof(sgx_ec256_signature_t, x) == offsetof(general_secp256r1_signature_t, x), SGX_GENERAL_KEY_TYPE_ERROR_MSG);
static_assert(offsetof(sgx_ec256_signature_t, y) == offsetof(general_secp256r1_signature_t, y), SGX_GENERAL_KEY_TYPE_ERROR_MSG);

#ifdef ENCLAVE_CODE

namespace std
{
	template<class T, size_t Size>
	inline reverse_iterator<T *> rbegin(T(&_Array)[Size])
	{	// get beginning of reversed array
		return (reverse_iterator<T *>(_Array + Size));
	}

	template<class T, size_t Size>
	inline reverse_iterator<T *> rend(T(&_Array)[Size])
	{	// get end of reversed array
		return (reverse_iterator<T *>(_Array));
	}
}

#endif // ENCLAVE_CODE

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

	std::reverse(std::begin(outSharedkey->s), std::end(outSharedkey->s));

	EVP_PKEY_CTX_free(ctx);
	return true;
}

bool ECKeySignOpenSSL2SGX(const ECDSA_SIG * inSign, sgx_ec256_signature_t * outSign)
{
	if (!inSign || !outSign)
	{
		return false;
	}

	const BIGNUM* r = nullptr;
	const BIGNUM* s = nullptr;
	ECDSA_SIG_get0(inSign, &r, &s);

	if (BN_num_bytes(r) != SGX_ECP256_KEY_SIZE ||
		BN_num_bytes(s) != SGX_ECP256_KEY_SIZE)
	{
		return false;
	}

	uint8_t* signX = reinterpret_cast<uint8_t*>(outSign->x);
	uint8_t* signY = reinterpret_cast<uint8_t*>(outSign->y);
	BN_bn2bin(r, signX);
	BN_bn2bin(s, signY);
	std::reverse(&signX[0], &signX[SGX_ECP256_KEY_SIZE]);
	std::reverse(&signY[0], &signY[SGX_ECP256_KEY_SIZE]);

	return true;
}

bool ECKeySignSGX2OpenSSL(const sgx_ec256_signature_t * inSign, ECDSA_SIG * outSign)
{
	if (!inSign || !outSign)
	{
		return false;
	}

	BIGNUM* r = BN_new();
	BIGNUM* s = BN_new();
	if (!r || !s)
	{
		BN_free(r);
		BN_free(s);
		return false;
	}

	std::vector<uint8_t> buffer(std::rbegin(inSign->x), std::rend(inSign->x));

	BN_bin2bn(buffer.data(), static_cast<int>(buffer.size()), r);

	buffer.assign(std::rbegin(inSign->y), std::rend(inSign->y));
	BN_bin2bn(buffer.data(), static_cast<int>(buffer.size()), s);

	if (BN_num_bytes(r) != SGX_ECP256_KEY_SIZE ||
		BN_num_bytes(s) != SGX_ECP256_KEY_SIZE)
	{
		BN_free(r);
		BN_free(s);
		return false;
	}

	int opensslRes = 0;

	opensslRes = ECDSA_SIG_set0(outSign, r, s); //The ownership of r and s is changed here!
	if (opensslRes != 1)
	{
		BN_free(r);
		BN_free(s);
		return false;
	}

	return true;
}
