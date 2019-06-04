#pragma once

#include <cstdint>
#include <cstring>

#include <array>

#include "general_key_types.h"

namespace Decent
{
	//General binary types:

	typedef std::array<uint8_t, GENERAL_128BIT_16BYTE_SIZE> General128BitBinary;
	typedef std::array<uint8_t, GENERAL_256BIT_32BYTE_SIZE> General256BitBinary;

	//128-bit types:

	typedef General128BitBinary General128BitKey;
	typedef General128BitBinary General128Tag;

	//256-bit types:

	typedef General256BitBinary General256BitKey;
	typedef General256BitBinary General256Hash;

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
}
