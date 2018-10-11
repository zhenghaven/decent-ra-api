#pragma once

#include <cstdint>
#include <cstring>

#include <array>

#include "general_key_types.h"

typedef std::array<uint8_t, GENERAL_128BIT_16BYTE_SIZE> GeneralAES128BitKey;
typedef std::array<uint8_t, GENERAL_256BIT_32BYTE_SIZE> General256Hash;

struct PrivateKeyWrap
{
	general_secp256r1_private_t m_prvKey;

	PrivateKeyWrap()
	{}

	PrivateKeyWrap(const general_secp256r1_private_t& prvKey) :
		m_prvKey(prvKey)
	{}

	PrivateKeyWrap(const PrivateKeyWrap& other) :
		m_prvKey(other.m_prvKey)
	{}

	~PrivateKeyWrap()
	{
		std::memset(&m_prvKey, 0, sizeof(general_secp256r1_private_t));
	}
};
