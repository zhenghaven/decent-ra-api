#include "AesGcmCommLayer.h"

#include "../Common.h"
#include "../GeneralKeyTypes.h"

#include "../Tools/Crypto.h"

#include "NetworkException.h"
#include "ConnectionBase.h"

using namespace Decent::Net;

namespace
{
	constexpr size_t PACK_BLOCK_SIZE = GENERAL_512BIT_64BYTE_SIZE * GENERAL_BITS_PER_BYTE;

	inline std::string Bin2String(const std::vector<uint8_t>& bin)
	{
		static_assert(sizeof(std::string::value_type) == sizeof(std::vector<uint8_t>::value_type), "This platform has sizeof(char) != sizeof(uint8_t)");

		return std::string(reinterpret_cast<const char*>(bin.data()),
			               reinterpret_cast<const char*>(bin.data()) + bin.size());
	}
}

AesGcmCommLayer::AesGcmCommLayer(const uint8_t (&sKey)[GENERAL_128BIT_16BYTE_SIZE], ConnectionBase* connection) :
	m_key(sKey),
	m_connection(connection)
{
}

AesGcmCommLayer::AesGcmCommLayer(const AesGcm128bKeyType & sKey, ConnectionBase* connection) :
	m_key(sKey),
	m_connection(connection)
{
}

AesGcmCommLayer::AesGcmCommLayer(AesGcmCommLayer && other) :
	m_key(std::move(other.m_key)),
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
		m_key = std::forward<decltype(m_key)>(other.m_key);

		ConnectionBase* tmpCnt = m_connection;
		m_connection = other.m_connection;
		other.m_connection = tmpCnt;
	}
	return *this;
}

AesGcmCommLayer::operator bool() const
{
	return true;
}

std::string AesGcmCommLayer::DecryptMsg(const std::string & inMsg)
{
	std::vector<uint8_t> meta; //Not used here.
	std::vector<uint8_t> res;
	Tools::QuickAesGcmUnpack(m_key.m_key, inMsg, meta, res, nullptr, PACK_BLOCK_SIZE);

	return Bin2String(res);
}

std::string AesGcmCommLayer::EncryptMsg(const std::string & inMsg)
{
	General128Tag tag; //Not used here.
	return Bin2String(
		Tools::QuickAesGcmPack(m_key.m_key, std::array<uint8_t, 0>(), std::array<uint8_t, 0>(), inMsg, tag, PACK_BLOCK_SIZE));
}

std::vector<uint8_t> AesGcmCommLayer::DecryptMsg(const std::vector<uint8_t>& inMsg)
{
	std::vector<uint8_t> meta; //Not used here.
	std::vector<uint8_t> res;
	Tools::QuickAesGcmUnpack(m_key.m_key, inMsg, meta, res, nullptr, PACK_BLOCK_SIZE);

	return res;
}

std::vector<uint8_t> AesGcmCommLayer::EncryptMsg(const std::vector<uint8_t>& inMsg)
{
	General128Tag tag; //Not used here.
	return Tools::QuickAesGcmPack(m_key.m_key, std::array<uint8_t, 0>(), std::array<uint8_t, 0>(), inMsg, tag, PACK_BLOCK_SIZE);
}

void AesGcmCommLayer::SetConnectionPtr(ConnectionBase& cnt)
{
	m_connection = &cnt;
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
	m_connection->ReceivePack(encrypted);
	
	outMsg = DecryptMsg(encrypted);
}

std::vector<uint8_t> AesGcmCommLayer::ReceiveBinary()
{
	if (!*this)
	{
		throw ConnectionNotEstablished();
	}

	std::vector<uint8_t> encrypted;
	m_connection->ReceivePack(encrypted);

	return DecryptMsg(encrypted);
}

void AesGcmCommLayer::SendRaw(const void * buf, const size_t size)
{
	if (!*this)
	{
		throw ConnectionNotEstablished();
	}

	std::vector<uint8_t> encrypted = EncryptMsg(
		std::vector<uint8_t>(static_cast<const uint8_t*>(buf), static_cast<const uint8_t*>(buf) + size));

	m_connection->SendPack(encrypted);
}

