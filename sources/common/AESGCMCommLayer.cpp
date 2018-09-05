#include "AESGCMCommLayer.h"

#include <algorithm>
#include <iterator>

#include <sgx_tcrypto.h>
#include <sgx_trts.h>

#ifdef ENCLAVE_CODE
#include <rapidjson/document.h>
#else
#include <json/json.h>
#endif // ENCLAVE_CODE

#include "DataCoding.h"
#include "JsonTools.h"
#include "CommonTool.h"

constexpr char AESGCMCommLayer::sk_LabelRoot[];
constexpr char AESGCMCommLayer::sk_LabelNonce[];
constexpr char AESGCMCommLayer::sk_LabelMac[];
constexpr char AESGCMCommLayer::sk_LabelMsg[];

AESGCMCommLayer::AESGCMCommLayer(const uint8_t sKey[GENERAL_128BIT_16BYTE_SIZE], const std::string& senderID, SendFunctionType sendFunc) :
	m_senderID(senderID),
	m_sendFunc(sendFunc)
{
	std::copy(sKey, sKey + GENERAL_128BIT_16BYTE_SIZE, m_sk.begin());
}

AESGCMCommLayer::AESGCMCommLayer(const AesGcm128bKeyType & sKey, const std::string& senderID, SendFunctionType sendFunc) :
	m_senderID(senderID),
	m_sendFunc(sendFunc)
{
	std::copy(sKey.begin(), sKey.end(), m_sk.begin());
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

	if (!jsonRoot.JSON_HAS_MEMBER(sk_LabelRoot) || !jsonRoot[sk_LabelRoot].JSON_IS_OBJECT() ||
		!jsonRoot[sk_LabelRoot].JSON_HAS_MEMBER(sk_LabelNonce) || !jsonRoot[sk_LabelRoot][sk_LabelNonce].JSON_IS_STRING() ||
		!jsonRoot[sk_LabelRoot].JSON_HAS_MEMBER(sk_LabelMac) || !jsonRoot[sk_LabelRoot][sk_LabelMac].JSON_IS_STRING() ||
		!jsonRoot[sk_LabelRoot].JSON_HAS_MEMBER(sk_LabelMsg) || !jsonRoot[sk_LabelRoot][sk_LabelMsg].JSON_IS_STRING())
	{
		return false;
	}

	GcmIvType iv;
	DeserializeStruct(iv, jsonRoot[sk_LabelRoot][sk_LabelNonce].JSON_AS_STRING());
	sgx_aes_gcm_128bit_tag_t macTag;
	DeserializeStruct(macTag, jsonRoot[sk_LabelRoot][sk_LabelMac].JSON_AS_STRING());
	std::vector<uint8_t> encryptedMsg;
	DeserializeStruct(encryptedMsg, jsonRoot[sk_LabelRoot][sk_LabelMsg].JSON_AS_STRING());

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

	JsonCommonSetString(doc, jsonRoot, sk_LabelNonce, SerializeStruct(iv));
	JsonCommonSetString(doc, jsonRoot, sk_LabelMac, SerializeStruct(macTag));
	JsonCommonSetString(doc, jsonRoot, sk_LabelMsg, SerializeStruct(encryptedMsg.data(), encryptedMsg.size()));

	JSON_EDITION::Value jsonRootRoot;
	JsonCommonSetObject(doc, jsonRootRoot, sk_LabelRoot, jsonRoot);
	
	std::string res = Json2StyleString(jsonRootRoot);
	COMMON_PRINTF("Send Encrypted Message: %s\n", res.c_str());

	return res;
}

bool AESGCMCommLayer::SendMsg(void* const connectionPtr, const std::string & msg, const char* appAttach) const
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

	return (*m_sendFunc)(connectionPtr, m_senderID.c_str(), outStr.c_str(), appAttach);
}
