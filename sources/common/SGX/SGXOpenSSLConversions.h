#pragma once

#include <openssl/obj_mac.h>

#define SGX_ECC256_CURVE_NAME NID_X9_62_prime256v1

typedef struct bignum_st BIGNUM;
typedef struct ec_point_st EC_POINT;
typedef struct ec_key_st EC_KEY;
typedef struct evp_pkey_st EVP_PKEY;
typedef struct ECDSA_SIG_st ECDSA_SIG;

typedef struct _sgx_ec256_private_t sgx_ec256_private_t;
typedef struct _sgx_ec256_public_t sgx_ec256_public_t;
typedef struct _sgx_ec256_dh_shared_t sgx_ec256_dh_shared_t;
typedef struct _sgx_ec256_signature_t sgx_ec256_signature_t;
typedef void* sgx_ecc_state_handle_t;

bool ECKeyOpenContext(sgx_ecc_state_handle_t* ctxPtr);

void ECKeyCloseContext(sgx_ecc_state_handle_t inCtx);

bool ECKeyPrvOpenSSL2SGX(const BIGNUM *inPrv, sgx_ec256_private_t *outPrv);

bool ECKeyPubOpenSSL2SGX(const EC_POINT *inPub, sgx_ec256_public_t *outPub, sgx_ecc_state_handle_t inCtx);

bool ECKeyPrvSGX2OpenSSL(const sgx_ec256_private_t *inPrv, BIGNUM *outPrv);

bool ECKeyPubSGX2OpenSSL(const sgx_ec256_public_t *inPub, EC_POINT *outPub, sgx_ecc_state_handle_t inCtx);

bool ECKeyGetPubFromPrv(const BIGNUM* inPrv, EC_POINT* outPub, sgx_ecc_state_handle_t inCtx);

bool ECKeyPairOpenSSL2SGX(const EC_KEY *inKeyPair, sgx_ec256_private_t *outPrv, sgx_ec256_public_t *outPub, sgx_ecc_state_handle_t inCtx);

bool ECKeyPairSGX2OpenSSL(const sgx_ec256_private_t *inPrv, const sgx_ec256_public_t *inPub, EC_KEY *outKeyPair, sgx_ecc_state_handle_t inCtx);

bool ECKeyPairSGX2OpenSSL(const sgx_ec256_private_t *inPrv, EC_KEY *outKeyPair, sgx_ecc_state_handle_t inCtx);

bool ECKeyPubSGX2OpenSSL(const sgx_ec256_public_t *inPub, EC_KEY *outKeyPair, sgx_ecc_state_handle_t inCtx);

bool ECKeyCalcSharedKey(EVP_PKEY* inKey, EVP_PKEY* inPeerKey, sgx_ec256_dh_shared_t *outSharedkey);

bool ECKeySignOpenSSL2SGX(const ECDSA_SIG* inSign, sgx_ec256_signature_t* outSign);

bool ECKeySignSGX2OpenSSL(const sgx_ec256_signature_t* inSign, ECDSA_SIG* outSign);
