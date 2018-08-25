#include "AESGCMCommLayer.h"

#include <cstdlib>

#include <sgx_tcrypto.h>
#include <sgx_trts.h>

#ifdef ENCLAVE_CODE
#include <rapidjson/document.h>
#include <Enclave_t.h>
#define JSON_HAS_MEMBER HasMember
#define JSON_IS_OBJECT IsObject
#define JSON_IS_STRING IsString
#define JSON_AS_STRING GetString
#else
#include <json/json.h>
#define JSON_HAS_MEMBER isMember
#define JSON_IS_OBJECT isObject
#define JSON_IS_STRING isString
#define JSON_AS_STRING asString
#endif // ENCLAVE_CODE

#include "DataCoding.h"
#include "JsonTools.h"
#include "CommonTool.h"

AESGCMCommLayer::AESGCMCommLayer(const uint8_t sKey[AES_GCM_128BIT_KEY_SIZE], const std::string& senderID, SendFunctionType sendFunc) :
	m_senderID(senderID),
	m_sendFunc(sendFunc)
{
	std::memcpy(m_sk.data(), &sKey[0], AES_GCM_128BIT_KEY_SIZE);
}

AESGCMCommLayer::AESGCMCommLayer(const AesGcm128bKeyType & sKey, const std::string& senderID, SendFunctionType sendFunc) :
	m_senderID(senderID),
	m_sendFunc(sendFunc)
{
	std::memcpy(m_sk.data(), sKey.data(), AES_GCM_128BIT_KEY_SIZE);
}

AESGCMCommLayer::AESGCMCommLayer(AesGcm128bKeyType & sKey, const std::string& senderID, SendFunctionType sendFunc) :
	m_senderID(senderID),
	m_sendFunc(sendFunc)
{
	m_sk.swap(sKey);
}

//AESGCMCommLayer::AESGCMCommLayer(const AESGCMCommLayer & other) :
//	m_senderID(other.m_senderID),
//	m_sendFunc(other.m_sendFunc)
//{
//	std::memcpy(m_sk.data(), other.m_sk.data(), AES_GCM_128BIT_KEY_SIZE);
//}

AESGCMCommLayer::AESGCMCommLayer(AESGCMCommLayer && other) :
	m_senderID(std::move(other.m_senderID)),
	m_sendFunc(other.m_sendFunc)
{
	m_sk.swap(other.m_sk);
}

AESGCMCommLayer::~AESGCMCommLayer()
{
}

bool AESGCMCommLayer::DecryptMsg(std::string & outMsg, const char * inMsg) const
{
	COMMON_PRINTF("Recv Encrypted Message: %s\n", inMsg);
	JSON_EDITION::JSON_DOCUMENT_TYPE jsonRoot;
	if (!ParseStr2Json(jsonRoot, inMsg))
	{
		return false;
	}

	if (!jsonRoot.JSON_HAS_MEMBER(LABEL_ROOT) || !jsonRoot[LABEL_ROOT].JSON_IS_OBJECT() ||
		!jsonRoot[LABEL_ROOT].JSON_HAS_MEMBER(LABEL_NONCE) || !jsonRoot[LABEL_ROOT][LABEL_NONCE].JSON_IS_STRING() ||
		!jsonRoot[LABEL_ROOT].JSON_HAS_MEMBER(LABEL_MAC) || !jsonRoot[LABEL_ROOT][LABEL_MAC].JSON_IS_STRING() ||
		!jsonRoot[LABEL_ROOT].JSON_HAS_MEMBER(LABEL_MSG) || !jsonRoot[LABEL_ROOT][LABEL_MSG].JSON_IS_STRING())
	{
		return false;
	}

	GcmIvType iv;
	DeserializeStruct(iv, jsonRoot[LABEL_ROOT][LABEL_NONCE].JSON_AS_STRING());
	sgx_aes_gcm_128bit_tag_t macTag;
	DeserializeStruct(macTag, jsonRoot[LABEL_ROOT][LABEL_MAC].JSON_AS_STRING());
	std::vector<uint8_t> encryptedMsg;
	DeserializeStruct(encryptedMsg, jsonRoot[LABEL_ROOT][LABEL_MSG].JSON_AS_STRING());

	outMsg.resize(encryptedMsg.size());

	sgx_status_t enclaveRet = sgx_rijndael128GCM_decrypt(
		reinterpret_cast<const sgx_aes_gcm_128bit_key_t*>(m_sk.data()),
		encryptedMsg.data(),
		static_cast<uint32_t>(encryptedMsg.size()),
		reinterpret_cast<uint8_t*>(&outMsg[0]),
		iv,
		static_cast<uint32_t>(GCM_IV_SIZE),
		nullptr,
		static_cast<uint32_t>(0),
		&macTag);

	return (enclaveRet == SGX_SUCCESS);
}

bool AESGCMCommLayer::DecryptMsg(std::string & outMsg, const std::string & inMsg) const
{
	return AESGCMCommLayer::DecryptMsg(outMsg, inMsg.c_str());
}

std::string AESGCMCommLayer::EncryptMsg(const std::string & msg) const
{
	JSON_EDITION::JSON_DOCUMENT_TYPE doc;
	JSON_EDITION::Value jsonRoot;
	
	GcmIvType iv;
	sgx_aes_gcm_128bit_tag_t macTag;
	std::vector<uint8_t> encryptedMsg;
	encryptedMsg.resize(msg.size());

	sgx_status_t enclaveRet = sgx_read_rand(iv, sizeof(GcmIvType));
	if (enclaveRet != SGX_SUCCESS)
	{
		return std::string();
	}

	enclaveRet = sgx_rijndael128GCM_encrypt(
		reinterpret_cast<const sgx_aes_gcm_128bit_key_t*>(m_sk.data()),
		reinterpret_cast<const uint8_t*>(msg.data()),
		static_cast<uint32_t>(msg.size()),
		encryptedMsg.data(),
		iv,
		static_cast<uint32_t>(GCM_IV_SIZE),
		nullptr,
		static_cast<uint32_t>(0),
		&macTag
	);
	if (enclaveRet != SGX_SUCCESS)
	{
		return std::string();
	}

	JsonCommonSetString(doc, jsonRoot, LABEL_NONCE, SerializeStruct(iv));
	JsonCommonSetString(doc, jsonRoot, LABEL_MAC, SerializeStruct(macTag));
	JsonCommonSetString(doc, jsonRoot, LABEL_MSG, SerializeStruct(encryptedMsg.data(), encryptedMsg.size()));

	JSON_EDITION::Value jsonRootRoot;
	JsonCommonSetObject(doc, jsonRootRoot, LABEL_ROOT, jsonRoot);
	
	std::string res = Json2StyleString(jsonRootRoot);
	COMMON_PRINTF("Send Encrypted Message: %s\n", res.c_str());

	return res;
}

bool AESGCMCommLayer::SendMsg(void* const connectionPtr, const std::string & msg) const
{
	if (msg.size() == 0)
	{
		return false;
	}

	std::string outStr;
	outStr = AESGCMCommLayer::EncryptMsg(msg);
	if (outStr.size() == 0)
	{
		return false;
	}

	return (*m_sendFunc)(connectionPtr, m_senderID.c_str(), outStr.c_str());
}
