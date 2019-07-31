#pragma once

#include <cstdint>

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

	namespace detail
	{
		void MemZeroize(void* buf, size_t size);
	}

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
			detail::MemZeroize(m_prvKey.r, sizeof(m_prvKey.r));
		}
	};

	template <size_t keySize>
	struct SecretKeyWrap
	{
		std::array<uint8_t, keySize> m_key;

		/** \brief	Default constructor. Constructs an empty key which can be filled later. */
		SecretKeyWrap() :
			m_key()
		{}

		/**
		 * \brief	Constructor. Copies the key from a raw array.
		 *
		 * \param	key	The key.
		 */
		SecretKeyWrap(const uint8_t(&key)[keySize]) :
			m_key()
		{
			std::copy(std::begin(key), std::end(key), m_key.begin());
		}

		/**
		 * \brief	Constructor. Copies the key from a std::array.
		 *
		 * \param	key	The key.
		 */
		SecretKeyWrap(const std::array<uint8_t, keySize>& key) :
			m_key(key)
		{}

		/**
		 * \brief	Constructor. Copies the key from a std::array. *And zeroize the memory of the origin.*
		 *
		 * \param [in,out]	key	The key.
		 */
		SecretKeyWrap(std::array<uint8_t, keySize>&& key) :
			m_key(key)
		{
			detail::MemZeroize(key.data(), key.size());
		}

		/** \brief	Destructor, which will zeroize the memory of the secret key. */
		~SecretKeyWrap()
		{
			detail::MemZeroize(m_key.data(), m_key.size());
		}
	};

	typedef SecretKeyWrap<GENERAL_128BIT_16BYTE_SIZE> G128BitSecretKeyWrap;
	typedef SecretKeyWrap<GENERAL_256BIT_32BYTE_SIZE> G256BitSecretKeyWrap;
}
