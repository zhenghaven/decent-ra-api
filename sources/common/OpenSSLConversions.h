#pragma once

#include <openssl/obj_mac.h>

#include "general_key_types.h"

#define ECC256_CURVE_NAME NID_X9_62_prime256v1

typedef struct bignum_st BIGNUM;
typedef struct ec_point_st EC_POINT;
typedef struct ec_key_st EC_KEY;
typedef struct evp_pkey_st EVP_PKEY;
typedef struct ECDSA_SIG_st ECDSA_SIG;

typedef void* ecc_state_handle_t;

int ECKeyOpenContext(ecc_state_handle_t* ctxPtr);

void ECKeyCloseContext(ecc_state_handle_t inCtx);

//OpenSSL -> General

int ECKeyPrvOpenSSL2General(const BIGNUM *inPrv, general_secp256r1_private_t *outPrv);

int ECKeyPubOpenSSL2General(const EC_POINT *inPub, general_secp256r1_public_t *outPub, ecc_state_handle_t inCtx);

int ECKeyPairOpenSSL2General(const EC_KEY *inKeyPair, general_secp256r1_private_t *outPrv, general_secp256r1_public_t *outPub, ecc_state_handle_t inCtx);

//General -> OpenSSL

int ECKeyPrvGeneral2OpenSSL(const general_secp256r1_private_t *inPrv, BIGNUM *outPrv);

int ECKeyPubGeneral2OpenSSL(const general_secp256r1_public_t *inPub, EC_POINT *outPub, ecc_state_handle_t inCtx);

int ECKeyPubGeneral2OpenSSL(const general_secp256r1_public_t *inPub, EC_KEY *outKeyPair, ecc_state_handle_t inCtx);

int ECKeyPairGeneral2OpenSSL(const general_secp256r1_private_t *inPrv, const general_secp256r1_public_t *inPub, EC_KEY *outKeyPair, ecc_state_handle_t inCtx);

//Misc

int ECKeyGetPubFromPrv(const BIGNUM* inPrv, EC_POINT* outPub, ecc_state_handle_t inCtx);
