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
	static constexpr char const sk_LabelRoot[]  = "AESGCM";
	static constexpr char const sk_LabelNonce[] = "Nonce";
	static constexpr char const sk_LabelMac[]   = "Mac";
	static constexpr char const sk_LabelMsg[]   = "Msg";

	static constexpr size_t GCM_IV_SIZE = 12;
	typedef uint8_t GcmIvType[GCM_IV_SIZE];

	static constexpr size_t AES_GCM_128BIT_KEY_SIZE = 16;
	typedef std::array<uint8_t, AES_GCM_128BIT_KEY_SIZE> AesGcm128bKeyType;

	typedef bool (*SendFunctionType)(void* const connectionPtr, const char* senderID, const char *msg, const char* appAttach);

public:
	AESGCMCommLayer() = delete;
	AESGCMCommLayer(const uint8_t sKey[AES_GCM_128BIT_KEY_SIZE], const std::string& senderID, SendFunctionType sendFunc);
	AESGCMCommLayer(const AesGcm128bKeyType& sKey, const std::string& senderID, SendFunctionType sendFunc);
	AESGCMCommLayer(AesGcm128bKeyType& sKey, const std::string& senderID, SendFunctionType sendFunc);
	//Copy is prohibited. 
	AESGCMCommLayer(const AESGCMCommLayer& other) = delete;
	AESGCMCommLayer(AESGCMCommLayer&& other);
	virtual ~AESGCMCommLayer();
	//Copy is prohibited. 
	AESGCMCommLayer& operator=(const AESGCMCommLayer& other) = delete;

	virtual bool DecryptMsg(std::string& outMsg, const char* inMsg) const override;
	virtual bool DecryptMsg(std::string& outMsg, const std::string& inMsg) const override;

	virtual std::string EncryptMsg(const std::string& msg) const override;
	virtual bool SendMsg(void* const connectionPtr, const std::string& msg, const char* appAttach) const override;

private:
	//std::unique_ptr<sgx_ec256_public_t> m_pubKey;
	AesGcm128bKeyType m_sk;
	//AesGcm128bKeyType* m_mk;
	SendFunctionType m_sendFunc;

	const std::string m_senderID;
};
