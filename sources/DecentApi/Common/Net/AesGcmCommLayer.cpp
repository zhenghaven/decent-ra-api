#include "AesGcmCommLayer.h"

#include "../Common.h"

#include "../Tools/Crypto.h"

#include "NetworkException.h"
#include "ConnectionBase.h"

using namespace Decent::Net;

namespace
{
	constexpr size_t PACK_BLOCK_SIZE = GENERAL_128BIT_16BYTE_SIZE * GENERAL_BITS_PER_BYTE;
}

AesGcmCommLayer::AesGcmCommLayer(const KeyType & sKey, const KeyType & mKey, ConnectionBase* connection) :
	m_sKey(sKey),
	m_mKey(mKey),
	m_connection(connection),
	m_streamBuf()
{
}

AesGcmCommLayer::AesGcmCommLayer(AesGcmCommLayer && other) :
	m_sKey(std::move(other.m_sKey)),
	m_mKey(std::move(other.m_mKey)),
	m_connection(other.m_connection),
	m_streamBuf(std::move(other.m_streamBuf))
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
		m_sKey = std::forward<decltype(m_sKey)>(other.m_sKey);
		m_mKey = std::forward<decltype(m_mKey)>(other.m_mKey);

		ConnectionBase* tmpCnt = m_connection;
		m_connection = other.m_connection;
		other.m_connection = tmpCnt;

		m_streamBuf = std::move(other.m_streamBuf);
	}
	return *this;
}

bool AesGcmCommLayer::IsValid() const
{
	return true;
}

size_t AesGcmCommLayer::SendRaw(const void * buf, const size_t size)
{
	if (!IsValid())
	{
		throw ConnectionNotEstablished();
	}

	std::vector<uint8_t> encBlock = EncryptMsg(
		std::vector<uint8_t>(static_cast<const uint8_t*>(buf), static_cast<const uint8_t*>(buf) + size));

	m_connection->SendContainer(encBlock);

	return size;
}

size_t AesGcmCommLayer::RecvRaw(void * buf, const size_t size)
{
	if (!IsValid())
	{
		throw ConnectionNotEstablished();
	}

	if (m_streamBuf.size() == 0)
	{
		//Buffer is clear, we need to poll data from remote first.

		std::vector<uint8_t> encBlock = m_connection->RecvContainer<std::vector<uint8_t> >();

		m_streamBuf = DecryptMsg(encBlock);
	}
	
	const bool isOutBufEnough = m_streamBuf.size() <= size;
	const size_t byteToCopy = isOutBufEnough ? m_streamBuf.size() : size;
	
	std::memcpy(buf, m_streamBuf.data(), byteToCopy);

	//Clean the buffer
	if (isOutBufEnough)
	{
		m_streamBuf.clear();
	}
	else
	{
		m_streamBuf = std::vector<uint8_t>(m_streamBuf.begin() + byteToCopy, m_streamBuf.end());
	}

	return byteToCopy;
}

void AesGcmCommLayer::SetConnectionPtr(ConnectionBase& cnt)
{
	m_connection = &cnt;
}

std::vector<uint8_t> AesGcmCommLayer::DecryptMsg(const std::vector<uint8_t>& inMsg)
{
	std::vector<uint8_t> meta; //Not used here.
	std::vector<uint8_t> res;
	Tools::QuickAesGcmUnpack(m_sKey.m_key, inMsg, std::array<uint8_t, 0>(), meta, res, nullptr, PACK_BLOCK_SIZE);

	return res;
}

std::vector<uint8_t> AesGcmCommLayer::EncryptMsg(const std::vector<uint8_t>& inMsg)
{
	General128Tag tag; //Not used here.
	return Tools::QuickAesGcmPack(m_sKey.m_key, std::array<uint8_t, 0>(), std::array<uint8_t, 0>(), inMsg, std::array<uint8_t, 0>(), tag, PACK_BLOCK_SIZE);
}
