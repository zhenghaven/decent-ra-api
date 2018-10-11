#include "AESGCMCommLayer.h"

#include <algorithm>
#include <iterator>

#include <sgx_tcrypto.h>

#include "GeneralKeyTypes.h"
#include "MbedTlsHelpers.h"
#include "DataCoding.h"
#include "JsonTools.h"
#include "CommonTool.h"
#include "Connection.h"

struct EncryptedStruct
{
	general_aes_128bit_key m_mac;
	suggested_aesgcm_iv m_iv;

#ifdef _MSC_VER
#pragma warning(push)
	/* Disable warning that array payload has size 0 */
#ifdef __INTEL_COMPILER
#pragma warning ( disable:94 )
#else
#pragma warning ( disable: 4200 )
#endif
#endif
	char m_msg[];
#ifdef _MSC_VER
#pragma warning(pop)
#endif
};

AESGCMCommLayer::AESGCMCommLayer(const uint8_t sKey[GENERAL_128BIT_16BYTE_SIZE])
{
	std::copy(sKey, sKey + GENERAL_128BIT_16BYTE_SIZE, m_sk.begin());
}

AESGCMCommLayer::AESGCMCommLayer(const AesGcm128bKeyType & sKey)
{
	std::copy(sKey.begin(), sKey.end(), m_sk.begin());
}

AESGCMCommLayer::AESGCMCommLayer(AesGcm128bKeyType & sKey) :
	AESGCMCommLayer(std::move(sKey))
{
}

AESGCMCommLayer::AESGCMCommLayer(AesGcm128bKeyType && sKey) :
	m_sk(sKey)
{
}

//AESGCMCommLayer::AESGCMCommLayer(const AESGCMCommLayer & other) :
//	m_senderID(other.m_senderID),
//	m_sendFunc(other.m_sendFunc)
//{
//	std::copy(other.m_sk.begin(), other.m_sk.end(), m_sk.begin());
//}

AESGCMCommLayer::AESGCMCommLayer(AESGCMCommLayer && other)
{
	m_sk.swap(other.m_sk);
}

AESGCMCommLayer::~AESGCMCommLayer()
{
}

bool AESGCMCommLayer::DecryptMsg(std::string & outMsg, const char * inMsg) const
{
	return AESGCMCommLayer::DecryptMsg(outMsg, std::string(inMsg));
}

bool AESGCMCommLayer::DecryptMsg(std::string & outMsg, const std::string & inMsg) const
{
	if (inMsg.size() <= sizeof(EncryptedStruct))
	{
		return false;
	}
	const EncryptedStruct& encryptedStruct = reinterpret_cast<const EncryptedStruct&>(inMsg[0]);

	size_t messageSize = inMsg.size() - sizeof(EncryptedStruct);
	outMsg.resize(messageSize);

	sgx_status_t enclaveRet = sgx_rijndael128GCM_decrypt(
		reinterpret_cast<const sgx_aes_gcm_128bit_key_t*>(m_sk.data()),
		reinterpret_cast<const uint8_t*>(&encryptedStruct.m_msg),
		static_cast<uint32_t>(messageSize),
		reinterpret_cast<uint8_t*>(&outMsg[0]),
		encryptedStruct.m_iv,
		static_cast<uint32_t>(SUGGESTED_AESGCM_IV_SIZE),
		nullptr,
		static_cast<uint32_t>(0),
		&encryptedStruct.m_mac);

	return (enclaveRet == SGX_SUCCESS);
}

bool AESGCMCommLayer::EncryptMsg(std::string & outMsg, const std::string & inMsg) const
{
	outMsg.resize(inMsg.size() + sizeof(EncryptedStruct));

	EncryptedStruct& encryptedStruct = reinterpret_cast<EncryptedStruct&>(outMsg[0]);

	void* drbgCtx;
	MbedTlsHelper::DrbgInit(drbgCtx);
	int mbedRet = MbedTlsHelper::DrbgRandom(drbgCtx, encryptedStruct.m_iv, SUGGESTED_AESGCM_IV_SIZE);
	MbedTlsHelper::DrbgFree(drbgCtx);
	if (mbedRet != 0)
	{
		return false;
	}

	sgx_status_t enclaveRet = sgx_rijndael128GCM_encrypt(
		reinterpret_cast<const sgx_aes_gcm_128bit_key_t*>(m_sk.data()),
		reinterpret_cast<const uint8_t*>(inMsg.data()),
		static_cast<uint32_t>(inMsg.size()),
		reinterpret_cast<uint8_t*>(&encryptedStruct.m_msg),
		encryptedStruct.m_iv,
		static_cast<uint32_t>(SUGGESTED_AESGCM_IV_SIZE),
		nullptr,
		static_cast<uint32_t>(0),
		&encryptedStruct.m_mac
	);

	return (enclaveRet == SGX_SUCCESS);
}

bool AESGCMCommLayer::ReceiveMsg(void * const connectionPtr, std::string & outMsg) const
{
	std::string encrypted;
	if (!StaticConnection::Receive(connectionPtr, encrypted))
	{
		return false;
	}
	return DecryptMsg(outMsg, encrypted);
}

bool AESGCMCommLayer::SendMsg(void * const connectionPtr, const std::string & inMsg) const
{
	std::string encrypted;
	if (!EncryptMsg(encrypted, inMsg))
	{
		return false;
	}
	return StaticConnection::Send(connectionPtr, encrypted);
}

