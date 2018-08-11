#pragma once

#include <string>
#include <vector>

//Forward declarations:
struct _sgx_ec256_public_t;
typedef _sgx_ec256_public_t sgx_ec256_public_t;
struct _sgx_ec256_signature_t;
typedef _sgx_ec256_signature_t sgx_ec256_signature_t;
#define SGX_CMAC_KEY_SIZE               16
typedef uint8_t sgx_ec_key_128bit_t[SGX_CMAC_KEY_SIZE];
#define SGX_AESGCM_MAC_SIZE             16
typedef uint8_t sgx_aes_gcm_128bit_tag_t[SGX_AESGCM_MAC_SIZE];
typedef struct x509_st X509;

std::string SerializePubKey(const sgx_ec256_public_t& pubKey);

void DeserializePubKey(const std::string& inPubKeyStr, sgx_ec256_public_t& outPubKey);

std::string SerializeSignature(const sgx_ec256_signature_t& sign);

void DeserializeSignature(const std::string& inSignStr, sgx_ec256_signature_t& outSign);

std::string SerializeKey(const sgx_ec_key_128bit_t& key);

void DeserializeKey(const std::string& inPubStr, sgx_ec_key_128bit_t& outKey);

std::string SerializeStruct(const uint8_t* ptr, size_t size);
template<typename T>
inline std::string SerializeStruct(const T& data)
{
	return SerializeStruct(reinterpret_cast<const uint8_t*>(&data), sizeof(T));
}

void DeserializeStruct(const std::string& inStr, void* ptr, size_t size);
template<typename T>
inline void DeserializeStruct(const std::string& inStr, T& outData)
{
	DeserializeStruct(inStr, static_cast<void*>(&outData), sizeof(T));
}

void LoadX509CertsFromStr(std::vector<X509*>& outCerts, const std::string& certStr);

bool VerifyIasReportCert(X509* root, const std::vector<X509*>& certsInHeader);

bool VerifyIasReportSignature(const std::string& data, std::vector<uint8_t> signature, X509* cert);

void FreeX509Cert(X509** cert);

void FreeX509Cert(std::vector<X509*>& certs);
