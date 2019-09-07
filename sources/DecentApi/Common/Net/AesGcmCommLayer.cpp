#include "AesGcmCommLayer.h"

#include "../Common.h"

#include "../Tools/Crypto.h"

#include "../MbedTls/Kdf.h"

#include "NetworkException.h"
#include "ConnectionBase.h"

using namespace Decent::Net;

namespace
{
	static constexpr size_t PACK_BLOCK_SIZE = GENERAL_128BIT_16BYTE_SIZE * GENERAL_BITS_PER_BYTE;

	static constexpr char const gsk_secKeyDerLabel[] = "next_secret_key";
	static constexpr char const gsk_makKeyDerLabel[] = "next_maskin_key";
}

AesGcmCommLayer::AesGcmCommLayer(const KeyType & sKey, const KeyType & mKey, ConnectionBase* connection) :
	m_selfSecKey(sKey),
	m_selfMakKey(mKey),
	m_selfAddData(),
	m_peerSecKey(sKey),
	m_peerMakKey(mKey),
	m_peerAddData(),
	m_connection(connection),
	m_streamBuf()
{
	RefreshSelfAddData();
	RefreshPeerAddData();
}

AesGcmCommLayer::AesGcmCommLayer(AesGcmCommLayer && other) :
	m_selfSecKey(std::move(other.m_selfSecKey)),
	m_selfMakKey(std::move(other.m_selfMakKey)),
	m_selfAddData(std::move(other.m_selfAddData)),
	m_peerSecKey(std::move(other.m_peerSecKey)),
	m_peerMakKey(std::move(other.m_peerMakKey)),
	m_peerAddData(std::move(other.m_peerAddData)),
	m_connection(other.m_connection),
	m_streamBuf(std::move(other.m_streamBuf))
{
	other.m_connection = nullptr;

	MbedTlsObj::ZeroizeContainer(other.m_selfAddData);
	MbedTlsObj::ZeroizeContainer(other.m_peerAddData);
	MbedTlsObj::ZeroizeContainer(other.m_streamBuf);
}

AesGcmCommLayer::~AesGcmCommLayer()
{
	MbedTlsObj::ZeroizeContainer(m_selfAddData);
	MbedTlsObj::ZeroizeContainer(m_peerAddData);
	MbedTlsObj::ZeroizeContainer(m_streamBuf);
}

AesGcmCommLayer & AesGcmCommLayer::operator=(AesGcmCommLayer && other)
{
	if (this != &other)
	{
		m_selfSecKey = std::forward<decltype(m_selfSecKey)>(other.m_selfSecKey);
		m_selfMakKey = std::forward<decltype(m_selfMakKey)>(other.m_selfMakKey);
		m_selfAddData = std::forward<decltype(m_selfAddData)>(other.m_selfAddData);
		m_peerSecKey = std::forward<decltype(m_peerSecKey)>(other.m_peerSecKey);
		m_peerMakKey = std::forward<decltype(m_peerMakKey)>(other.m_peerMakKey);
		m_peerAddData = std::forward<decltype(m_peerAddData)>(other.m_peerAddData);

		m_connection = other.m_connection;
		other.m_connection = nullptr;

		m_streamBuf = std::move(other.m_streamBuf);

		MbedTlsObj::ZeroizeContainer(other.m_selfAddData);
		MbedTlsObj::ZeroizeContainer(other.m_peerAddData);
		MbedTlsObj::ZeroizeContainer(other.m_streamBuf);
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
	Tools::QuickAesGcmUnpack(m_peerSecKey.m_key, inMsg, m_peerAddData, meta, res, nullptr, PACK_BLOCK_SIZE);

	CheckPeerKeysLifetime();

	return res;
}

std::vector<uint8_t> AesGcmCommLayer::EncryptMsg(const std::vector<uint8_t>& inMsg)
{
	General128Tag tag; //Not used here.

	std::vector<uint8_t> res =
		Tools::QuickAesGcmPack(m_selfSecKey.m_key, std::array<uint8_t, 0>(), std::array<uint8_t, 0>(), inMsg, m_selfAddData, tag, PACK_BLOCK_SIZE);

	CheckSelfKeysLifetime();

	return res;
}

void AesGcmCommLayer::CheckSelfKeysLifetime()
{
	if (m_selfAddData[2] >= sk_maxCounter)
	{
		RefreshSelfKeys();
	}
	else
	{
		++m_selfAddData[2];
	}
}

void AesGcmCommLayer::CheckPeerKeysLifetime()
{
	if (m_peerAddData[2] >= sk_maxCounter)
	{
		RefreshPeerKeys();
	}
	else
	{
		++m_peerAddData[2];
	}
}

void AesGcmCommLayer::RefreshSelfKeys()
{
	using namespace Decent::MbedTlsObj;

	KeyType tmpSecKey;
	KeyType tmpMakKey;

	HKDF<HashType::SHA256>(m_selfSecKey.m_key, gsk_secKeyDerLabel, std::array<uint8_t, 0>(), tmpSecKey.m_key);
	HKDF<HashType::SHA256>(m_selfMakKey.m_key, gsk_makKeyDerLabel, std::array<uint8_t, 0>(), tmpMakKey.m_key);

	m_selfSecKey = tmpSecKey;
	m_selfMakKey = tmpMakKey;

	RefreshSelfAddData();
}

void AesGcmCommLayer::RefreshPeerKeys()
{
	using namespace Decent::MbedTlsObj;

	KeyType tmpSecKey;
	KeyType tmpMakKey;

	HKDF<HashType::SHA256>(m_peerSecKey.m_key, gsk_secKeyDerLabel, std::array<uint8_t, 0>(), tmpSecKey.m_key);
	HKDF<HashType::SHA256>(m_peerMakKey.m_key, gsk_makKeyDerLabel, std::array<uint8_t, 0>(), tmpMakKey.m_key);

	m_peerSecKey = tmpSecKey;
	m_peerMakKey = tmpMakKey;

	RefreshPeerAddData();
}

void AesGcmCommLayer::RefreshSelfAddData()
{
	static_assert(
		(sizeof(decltype(m_selfAddData)::value_type) * std::tuple_size<decltype(m_selfAddData)>::value) ==
		(decltype(m_selfMakKey)::GetTotalSize() + sizeof(decltype(m_selfAddData)::value_type)),
		"The size of additional data doesn't match the size actually needed.");

	std::memcpy(m_selfAddData.data(), m_selfMakKey.m_key.data(), decltype(m_selfMakKey)::GetTotalSize());

	static_assert(std::tuple_size<decltype(m_selfAddData)>::value == 3, "The length of addtional data is too small.");

	m_selfAddData[2] = 0;
}

void AesGcmCommLayer::RefreshPeerAddData()
{
	static_assert(
		(sizeof(decltype(m_peerAddData)::value_type) * std::tuple_size<decltype(m_peerAddData)>::value) ==
		(decltype(m_peerMakKey)::GetTotalSize() + sizeof(decltype(m_peerAddData)::value_type)),
		"The size of additional data doesn't match the size actually needed.");

	std::memcpy(m_peerAddData.data(), m_peerMakKey.m_key.data(), decltype(m_peerMakKey)::GetTotalSize());

	static_assert(std::tuple_size<decltype(m_peerAddData)>::value == 3, "The length of addtional data is too small.");

	m_peerAddData[2] = 0;
}
