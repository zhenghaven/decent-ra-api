#pragma once

#include "SecureCommLayer.h"

#include <memory>
#include <array>

//typedef struct _sgx_ec256_public_t sgx_ec256_public_t;
//#define SGX_CMAC_KEY_SIZE               16
//typedef uint8_t sgx_ec_key_128bit_t[SGX_CMAC_KEY_SIZE];
//#define SGX_AESGCM_KEY_SIZE             16
//typedef uint8_t sgx_aes_gcm_128bit_key_t[SGX_AESGCM_KEY_SIZE];

class AESGCMCommLayer : virtual public SecureCommLayer
{
public:
	static constexpr char* LABEL_ROOT  = "AESGCM";
	static constexpr char* LABEL_NONCE = "Nonce";
	static constexpr char* LABEL_MAC   = "Mac";
	static constexpr char* LABEL_MSG   = "Msg";

	static constexpr size_t GCM_IV_SIZE = 12;
	typedef uint8_t GcmIvType[GCM_IV_SIZE];

	static constexpr size_t AES_GCM_128BIT_KEY_SIZE = 16;
	typedef std::array<uint8_t, AES_GCM_128BIT_KEY_SIZE> AesGcm128bKeyType;

	typedef bool (*SendFunctionType)(void* const connectionPtr, const char *msg);

public:
	AESGCMCommLayer() = delete;
	AESGCMCommLayer(const uint8_t (&sKey)[AES_GCM_128BIT_KEY_SIZE], SendFunctionType sendFunc);
	AESGCMCommLayer(const AesGcm128bKeyType& sKey, SendFunctionType sendFunc);
	AESGCMCommLayer(AesGcm128bKeyType& sKey, SendFunctionType sendFunc);
	AESGCMCommLayer(const AESGCMCommLayer& other);
	AESGCMCommLayer(AESGCMCommLayer&& other);
	virtual ~AESGCMCommLayer();

	virtual bool DecryptMsg(std::string& outMsg, const char* inMsg) override;
	virtual bool DecryptMsg(std::string& outMsg, const std::string& inMsg) override;

	virtual std::string EncryptMsg(const std::string& msg) override;
	virtual bool SendMsg(void* const connectionPtr, const std::string& msg) override;

private:
	//std::unique_ptr<sgx_ec256_public_t> m_pubKey;
	AesGcm128bKeyType m_sk;
	//AesGcm128bKeyType* m_mk;
	SendFunctionType m_sendFunc;
};
