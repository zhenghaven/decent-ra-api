#include "AesGcmCommLayer.h"

#include <mbedTLScpp/Hkdf.hpp>

#include "../Common.h"

#include "../Tools/Crypto.h"

#include "NetworkException.h"
#include "ConnectionBase.h"

using namespace Decent::Net;

namespace
{
	static constexpr size_t PACK_BLOCK_SIZE = 128;

	static constexpr char const gsk_secKeyDerLabel[] = "next_secret_key";
	static constexpr char const gsk_makKeyDerLabel[] = "next_maskin_key";
}

AesGcmCommLayer::AesGcmCommLayer(const KeyType & sKey, const KeyType & mKey, ConnectionBase* connection) :
	m_selfSecKey(sKey),
	m_selfMakKey(mKey),
	m_selfAddData(),
	m_selfAesGcm(),
	m_peerSecKey(sKey),
	m_peerMakKey(mKey),
	m_peerAddData(),
	m_peerAesGcm(),
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
	m_selfAesGcm(std::move(other.m_selfAesGcm)),
	m_peerSecKey(std::move(other.m_peerSecKey)),
	m_peerMakKey(std::move(other.m_peerMakKey)),
	m_peerAddData(std::move(other.m_peerAddData)),
	m_peerAesGcm(std::move(other.m_peerAesGcm)),
	m_connection(other.m_connection),
	m_streamBuf(std::move(other.m_streamBuf))
{
	other.m_connection = nullptr;
}

AesGcmCommLayer::~AesGcmCommLayer()
{}

AesGcmCommLayer & AesGcmCommLayer::operator=(AesGcmCommLayer && other)
{
	if (this != &other)
	{
		m_selfSecKey = std::forward<decltype(m_selfSecKey)>(other.m_selfSecKey);
		m_selfMakKey = std::forward<decltype(m_selfMakKey)>(other.m_selfMakKey);
		m_selfAddData = std::forward<decltype(m_selfAddData)>(other.m_selfAddData);
		m_selfAesGcm = std::forward<decltype(m_selfAesGcm)>(other.m_selfAesGcm);
		m_peerSecKey = std::forward<decltype(m_peerSecKey)>(other.m_peerSecKey);
		m_peerMakKey = std::forward<decltype(m_peerMakKey)>(other.m_peerMakKey);
		m_peerAddData = std::forward<decltype(m_peerAddData)>(other.m_peerAddData);
		m_peerAesGcm = std::forward<decltype(m_peerAesGcm)>(other.m_peerAesGcm);

		m_connection = other.m_connection;
		other.m_connection = nullptr;

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
		m_streamBuf.erase(m_streamBuf.begin(), m_streamBuf.begin() + byteToCopy);
	}

	return byteToCopy;
}

void AesGcmCommLayer::SetConnectionPtr(ConnectionBase& cnt)
{
	m_connection = &cnt;
}

mbedTLScpp::SecretVector<uint8_t> AesGcmCommLayer::DecryptMsg(const std::vector<uint8_t>& inMsg)
{
	using namespace mbedTLScpp;

	SecretVector<uint8_t> res;
	std::tie(res, std::ignore) = m_peerAesGcm->Unpack(
		CtnFullR(inMsg),
		CtnFullR(m_peerAddData),
		nullptr
	);

	CheckPeerKeysLifetime();

	return res;
}

std::vector<uint8_t> AesGcmCommLayer::EncryptMsg(const std::vector<uint8_t>& inMsg)
{
	using namespace mbedTLScpp;

	std::vector<uint8_t> res;
	std::tie(res, std::ignore) = m_selfAesGcm->Pack(
		CtnFullR(gsk_emptyCtn),
		CtnFullR(gsk_emptyCtn),
		CtnFullR(inMsg),
		CtnFullR(m_selfAddData)
	);

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
	using namespace mbedTLScpp;

	KeyType tmpSecKey;
	KeyType tmpMakKey;

	tmpSecKey = mbedTLScpp::Hkdf<HashType::SHA256, 128>(CtnFullR(m_selfSecKey), CtnFullR(gsk_secKeyDerLabel), CtnFullR(gsk_emptyCtn));
	tmpMakKey = mbedTLScpp::Hkdf<HashType::SHA256, 128>(CtnFullR(m_selfMakKey), CtnFullR(gsk_makKeyDerLabel), CtnFullR(gsk_emptyCtn));

	m_selfSecKey = tmpSecKey;
	m_selfMakKey = tmpMakKey;

	m_selfAesGcm = Internal::make_unique<Crypto::AesGcmPacker>(CtnFullR(m_selfSecKey), PACK_BLOCK_SIZE);

	RefreshSelfAddData();
}

void AesGcmCommLayer::RefreshPeerKeys()
{
	using namespace mbedTLScpp;

	KeyType tmpSecKey;
	KeyType tmpMakKey;

	tmpSecKey = mbedTLScpp::Hkdf<HashType::SHA256, 128>(CtnFullR(m_peerSecKey), CtnFullR(gsk_secKeyDerLabel), CtnFullR(gsk_emptyCtn));
	tmpMakKey = mbedTLScpp::Hkdf<HashType::SHA256, 128>(CtnFullR(m_peerMakKey), CtnFullR(gsk_makKeyDerLabel), CtnFullR(gsk_emptyCtn));

	m_peerSecKey = tmpSecKey;
	m_peerMakKey = tmpMakKey;

	m_peerAesGcm = Internal::make_unique<Crypto::AesGcmPacker>(CtnFullR(m_peerSecKey), PACK_BLOCK_SIZE);

	RefreshPeerAddData();
}

void AesGcmCommLayer::RefreshSelfAddData()
{
	static_assert(
		(sizeof(decltype(m_selfAddData)::value_type) * decltype(m_selfAddData)::sk_itemCount) ==
		(decltype(m_selfMakKey)::sk_itemCount + sizeof(decltype(m_selfAddData)::value_type)),
		"The size of additional data doesn't match the size actually needed.");

	static_assert(decltype(m_selfAddData)::sk_itemCount == 3, "The length of addtional data is too small.");

	std::memcpy(m_selfAddData.data(), m_selfMakKey.data(), decltype(m_selfMakKey)::sk_itemCount);

	m_selfAddData[2] = 0;
}

void AesGcmCommLayer::RefreshPeerAddData()
{
	static_assert(
		(sizeof(decltype(m_peerAddData)::value_type) * decltype(m_peerAddData)::sk_itemCount) ==
		(decltype(m_peerMakKey)::sk_itemCount + sizeof(decltype(m_peerAddData)::value_type)),
		"The size of additional data doesn't match the size actually needed.");

	static_assert(decltype(m_peerAddData)::sk_itemCount == 3, "The length of addtional data is too small.");

	std::memcpy(m_peerAddData.data(), m_peerMakKey.data(), decltype(m_peerMakKey)::sk_itemCount);

	m_peerAddData[2] = 0;
}
