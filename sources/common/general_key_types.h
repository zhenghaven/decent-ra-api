#pragma once

#ifndef GENERAL_KEY_TYPES
#define GENERAL_KEY_TYPES

#include <stdint.h>

#define GENERAL_128BIT_16BYTE_SIZE 16
#define GENERAL_256BIT_32BYTE_SIZE 32
#define GENERAL_512BIT_64BYTE_SIZE 64

#define SUGGESTED_AESGCM_IV_SIZE   12

#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(push, 1)

	//EC Key used in here is Prime256-r1 A.K.A NIST P-256, or secp256r1.

	typedef struct _general_secp256r1_shared_t
	{
		uint8_t s[GENERAL_256BIT_32BYTE_SIZE];
	} general_secp256r1_shared_t;

	typedef struct _general_secp256r1_private_t
	{
		uint8_t r[GENERAL_256BIT_32BYTE_SIZE];
	} general_secp256r1_private_t;

	typedef struct _general_secp256r1_public_t
	{
		uint8_t x[GENERAL_256BIT_32BYTE_SIZE];
		uint8_t y[GENERAL_256BIT_32BYTE_SIZE];
	} general_secp256r1_public_t;

	typedef struct _general_secp256r1_signature_t
	{
		uint8_t x[GENERAL_256BIT_32BYTE_SIZE];
		uint8_t y[GENERAL_256BIT_32BYTE_SIZE];
	} general_secp256r1_signature_t;

	typedef uint8_t general_aes_128bit_key[GENERAL_128BIT_16BYTE_SIZE];

	typedef uint8_t suggested_aesgcm_iv[SUGGESTED_AESGCM_IV_SIZE];

#pragma pack(pop)

#ifdef __cplusplus
}
#endif

#endif // !GENERAL_KEY_TYPES
