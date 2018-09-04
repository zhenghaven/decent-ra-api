#pragma once
#ifndef SGX_CONSTANTS_H
#define SGX_CONSTANTS_H

#include <cstdint>

#define SGX_QUOTE_UNLINKABLE_SIGNATURE 0
#define SGX_QUOTE_LINKABLE_SIGNATURE   1

#define SAMPLE_SP_IV_SIZE        12

//Key Derivation Function ID : 0x0001  AES-CMAC Entropy Extraction and Key Expansion
constexpr uint16_t SAMPLE_AES_CMAC_KDF_ID = 0x0001;
constexpr size_t   IAS_REQUEST_NONCE_SIZE = 32;

#endif // !SGX_CONSTANTS_H
