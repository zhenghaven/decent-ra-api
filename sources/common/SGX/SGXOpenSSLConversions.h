#pragma once

#include <string>

//#include <openssl/obj_mac.h>
#include "../OpenSSLConversions.h"

#define SGX_ECC256_CURVE_NAME NID_X9_62_prime256v1

//typedef struct bignum_st BIGNUM;
//typedef struct ec_point_st EC_POINT;
//typedef struct ec_key_st EC_KEY;
//typedef struct evp_pkey_st EVP_PKEY;
//typedef struct ECDSA_SIG_st ECDSA_SIG;

typedef struct _sgx_ec256_private_t sgx_ec256_private_t;
typedef struct _sgx_ec256_public_t sgx_ec256_public_t;
typedef struct _sgx_ec256_dh_shared_t sgx_ec256_dh_shared_t;
typedef struct _sgx_ec256_signature_t sgx_ec256_signature_t;
typedef void* sgx_ecc_state_handle_t;

__forceinline const general_secp256r1_public_t* SgxEc256Type2General(const sgx_ec256_public_t* x)
{
	return reinterpret_cast<const general_secp256r1_public_t*>(x);
}

__forceinline const general_secp256r1_private_t* SgxEc256Type2General(const sgx_ec256_private_t* x)
{
	return reinterpret_cast<const general_secp256r1_private_t*>(x);
}

__forceinline const general_secp256r1_shared_t* SgxEc256Type2General(const sgx_ec256_dh_shared_t* x)
{
	return reinterpret_cast<const general_secp256r1_shared_t*>(x);
}

__forceinline const general_secp256r1_signature_t* SgxEc256Type2General(const sgx_ec256_signature_t* x)
{
	return reinterpret_cast<const general_secp256r1_signature_t*>(x);
}

__forceinline general_secp256r1_public_t* SgxEc256Type2General(sgx_ec256_public_t* x)
{
	return reinterpret_cast<general_secp256r1_public_t*>(x);
}

__forceinline general_secp256r1_private_t* SgxEc256Type2General(sgx_ec256_private_t* x)
{
	return reinterpret_cast<general_secp256r1_private_t*>(x);
}

__forceinline general_secp256r1_shared_t* SgxEc256Type2General(sgx_ec256_dh_shared_t* x)
{
	return reinterpret_cast<general_secp256r1_shared_t*>(x);
}

__forceinline general_secp256r1_signature_t* SgxEc256Type2General(sgx_ec256_signature_t* x)
{
	return reinterpret_cast<general_secp256r1_signature_t*>(x);
}

__forceinline const general_secp256r1_public_t& SgxEc256Type2General(const sgx_ec256_public_t& x)
{
	return reinterpret_cast<const general_secp256r1_public_t&>(x);
}

__forceinline const general_secp256r1_private_t& SgxEc256Type2General(const sgx_ec256_private_t& x)
{
	return reinterpret_cast<const general_secp256r1_private_t&>(x);
}

__forceinline const general_secp256r1_shared_t& SgxEc256Type2General(const sgx_ec256_dh_shared_t& x)
{
	return reinterpret_cast<const general_secp256r1_shared_t&>(x);
}

__forceinline const general_secp256r1_signature_t& SgxEc256Type2General(const sgx_ec256_signature_t& x)
{
	return reinterpret_cast<const general_secp256r1_signature_t&>(x);
}

__forceinline general_secp256r1_public_t& SgxEc256Type2General(sgx_ec256_public_t& x)
{
	return reinterpret_cast<general_secp256r1_public_t&>(x);
}

__forceinline general_secp256r1_private_t& SgxEc256Type2General(sgx_ec256_private_t& x)
{
	return reinterpret_cast<general_secp256r1_private_t&>(x);
}

__forceinline general_secp256r1_shared_t& SgxEc256Type2General(sgx_ec256_dh_shared_t& x)
{
	return reinterpret_cast<general_secp256r1_shared_t&>(x);
}

__forceinline general_secp256r1_signature_t& SgxEc256Type2General(sgx_ec256_signature_t& x)
{
	return reinterpret_cast<general_secp256r1_signature_t&>(x);
}


bool ECKeyCalcSharedKey(EVP_PKEY* inKey, EVP_PKEY* inPeerKey, sgx_ec256_dh_shared_t *outSharedkey);

bool ECKeySignOpenSSL2SGX(const ECDSA_SIG* inSign, sgx_ec256_signature_t* outSign);

bool ECKeySignSGX2OpenSSL(const sgx_ec256_signature_t* inSign, ECDSA_SIG* outSign);

bool ECKeyPubSGX2Pem(const sgx_ec256_public_t& inPub, std::string& outPem);

bool ECKeyPubPem2SGX(const std::string& inPem, sgx_ec256_public_t& outPub);
