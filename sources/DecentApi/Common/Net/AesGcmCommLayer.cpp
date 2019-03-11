#include "AesGcmCommLayer.h"

#include "../Common.h"
#include "../GeneralKeyTypes.h"

#include "../Tools/DataCoding.h"
#include "../MbedTls/Drbg.h"

#include "NetworkException.h"
#include "Connection.h"

using namespace Decent::Net;
using namespace Decent::MbedTlsObj;

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

AesGcmCommLayer::AesGcmCommLayer(const uint8_t (&sKey)[GENERAL_128BIT_16BYTE_SIZE]) :
	m_gcm(sKey)
{
}

AesGcmCommLayer::AesGcmCommLayer(const AesGcm128bKeyType & sKey) :
	m_gcm(sKey)
{
}

AesGcmCommLayer::AesGcmCommLayer(AesGcmCommLayer && other) :
	m_gcm(std::move(other.m_gcm)),
	m_connection(other.m_connection)
{
	other.m_connection = nullptr;
}

AesGcmCommLayer::~AesGcmCommLayer()
{
}

AesGcmCommLayer & AesGcmCommLayer::operator=(AesGcmCommLayer && other)
{
	if (this != &other)
	{
		m_gcm = std::forward<GcmObjType>(other.m_gcm);

		void* tmpCnt = m_connection;
		m_connection = other.m_connection;
		other.m_connection = tmpCnt;
	}
	return *this;
}

AesGcmCommLayer::operator bool() const
{
	return m_gcm;
}

std::string AesGcmCommLayer::DecryptMsg(const void* inMsg, const size_t inSize)
{
	if (inSize <= sizeof(EncryptedStruct))
	{
		throw Exception("Invalid input parameters for function " "AesGcmCommLayer::DecryptMsg" ". The input message is even smaller than an empty encrypted message!");
	}

	const EncryptedStruct& encryptedStruct = *reinterpret_cast<const EncryptedStruct*>(inMsg);

	std::string res;

	size_t messageSize = inSize - sizeof(EncryptedStruct);
	res.resize(messageSize);

	try
	{
		m_gcm.DecryptStruct(
			&encryptedStruct.m_msg, messageSize,
			&res[0], res.size(),
			encryptedStruct.m_iv,
			encryptedStruct.m_mac);
	}
	catch (const std::exception& e)
	{
		throw Exception(std::string("Decryption failed with error: ") + e.what());
	}

	return std::move(res);
}

std::string AesGcmCommLayer::EncryptMsg(const void * inMsg, const size_t inSize)
{
	std::string res;
	res.resize(sizeof(EncryptedStruct) + inSize);

	EncryptedStruct& encryptedStruct = reinterpret_cast<EncryptedStruct&>(res[0]);

	try
	{
		Drbg drbg;
		drbg.RandStruct(encryptedStruct.m_iv);

		m_gcm.EncryptStruct(
			inMsg, inSize,
			&encryptedStruct.m_msg, inSize,
			encryptedStruct.m_iv,
			encryptedStruct.m_mac);
	}
	catch (const std::exception& e)
	{
		throw Exception(std::string("Encryption failed with error: ") + e.what());
	}

	return std::move(res);
}

void AesGcmCommLayer::SetConnectionPtr(void * const connectionPtr)
{
	m_connection = connectionPtr;
}

void AesGcmCommLayer::ReceiveRaw(void * buf, const size_t size)
{
	std::string msgBuf;
	ReceiveMsg(msgBuf);
	if (msgBuf.size() != size)
	{
		throw Exception("The size of received message does not match the size that requested!");
	}

	uint8_t* bytePtr = static_cast<uint8_t*>(buf);
	memcpy(bytePtr, msgBuf.data(), size);
}

void AesGcmCommLayer::ReceiveMsg(std::string & outMsg)
{
	if (!*this)
	{
		throw ConnectionNotEstablished();
	}

	std::string encrypted;
	StatConnection::ReceivePack(m_connection, encrypted);
	
	outMsg = DecryptMsg(encrypted);
}

void AesGcmCommLayer::SendRaw(const void * buf, const size_t size)
{
	if (!*this)
	{
		throw ConnectionNotEstablished();
	}

	std::string encrypted = EncryptMsg(buf, size);

	StatConnection::SendPack(m_connection, encrypted);
}

