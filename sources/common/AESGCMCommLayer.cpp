#include "AESGCMCommLayer.h"

#include "GeneralKeyTypes.h"
#include "MbedTlsHelpers.h"
#include "DataCoding.h"
#include "JsonTools.h"
#include "CommonTool.h"
#include "Connection.h"

struct EncryptedStruct
{
	general_128bit_tag m_mac;
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

AESGCMCommLayer::AESGCMCommLayer(const uint8_t (&sKey)[GENERAL_128BIT_16BYTE_SIZE]) :
	m_gcm(sKey)
{
}

AESGCMCommLayer::AESGCMCommLayer(const AesGcm128bKeyType & sKey) :
	m_gcm(sKey)
{
}

AESGCMCommLayer::AESGCMCommLayer(AESGCMCommLayer && other) :
	m_gcm(std::move(other.m_gcm))
{
}

AESGCMCommLayer::~AESGCMCommLayer()
{
}

AESGCMCommLayer & AESGCMCommLayer::operator=(AESGCMCommLayer && other)
{
	if (this != &other)
	{
		m_gcm = std::forward<MbedTlsObj::Aes128Gcm>(other.m_gcm);
	}
	return *this;
}

//bool AESGCMCommLayer::DecryptMsg(std::string & outMsg, const char * inMsg)
//{
//	return AESGCMCommLayer::DecryptMsg(outMsg, std::string(inMsg));
//}

bool AESGCMCommLayer::DecryptMsg(std::string & outMsg, const std::string & inMsg)
{
	if (inMsg.size() <= sizeof(EncryptedStruct))
	{
		return false;
	}
	const EncryptedStruct& encryptedStruct = reinterpret_cast<const EncryptedStruct&>(inMsg[0]);

	size_t messageSize = inMsg.size() - sizeof(EncryptedStruct);
	outMsg.resize(messageSize);

	bool res = m_gcm.Decrypt(
		reinterpret_cast<const uint8_t*>(&encryptedStruct.m_msg),
		reinterpret_cast<uint8_t*>(&outMsg[0]),
		messageSize,
		encryptedStruct.m_iv,
		SUGGESTED_AESGCM_IV_SIZE,
		nullptr,
		0,
		encryptedStruct.m_mac,
		sizeof(encryptedStruct.m_mac));

	return res;
}

bool AESGCMCommLayer::EncryptMsg(std::string & outMsg, const std::string & inMsg)
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

	bool res = m_gcm.Encrypt(
		reinterpret_cast<const uint8_t*>(inMsg.data()),
		reinterpret_cast<uint8_t*>(&encryptedStruct.m_msg),
		inMsg.size(),
		encryptedStruct.m_iv,
		SUGGESTED_AESGCM_IV_SIZE,
		nullptr,
		0,
		encryptedStruct.m_mac,
		sizeof(encryptedStruct.m_mac));

	return res;
}

bool AESGCMCommLayer::ReceiveMsg(void * const connectionPtr, std::string & outMsg)
{
	std::string encrypted;
	if (!StaticConnection::Receive(connectionPtr, encrypted))
	{
		return false;
	}
	return DecryptMsg(outMsg, encrypted);
}

bool AESGCMCommLayer::SendMsg(void * const connectionPtr, const std::string & inMsg)
{
	std::string encrypted;
	if (!EncryptMsg(encrypted, inMsg))
	{
		return false;
	}
	return StaticConnection::Send(connectionPtr, encrypted);
}

