#pragma once

#include <array>

#include "MbedTlsCppDefs.h"

namespace Decent
{
	namespace MbedTlsObj
	{
		namespace detail
		{
			void MemZeroize(void* buf, size_t size);
		}

		/**
		 * \brief	Zeroize any data held inside the container. This function won't affect the size or
		 * 			any other metadata of the container.
		 *
		 * \tparam	Container	Type of the container.
		 * \param [in,out]	cnt	The container.
		 */
		template<typename Container>
		inline void ZeroizeContainer(Container& cnt)
		{
			using namespace detail;
			MemZeroize(GetPtr(cnt), GetSize(cnt));
		}

		/**
		 * \brief	A secret key wrap. Memory will be zeroized at destruction.
		 *
		 * \tparam	keySize	Size of the key.
		 */
		template <size_t keySize>
		struct SecretKeyWrap
		{
			std::array<uint8_t, keySize> m_key;

			static constexpr size_t GetTotalSize()
			{
				return sizeof(typename decltype(m_key)::value_type) * keySize;
			}

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
				ZeroizeContainer(key);
			}

			/**
			 * \brief	Copy Constructor
			 *
			 * \param	rhs	The right hand side.
			 */
			SecretKeyWrap(const SecretKeyWrap& rhs) :
				m_key(rhs.m_key)
			{}

			/**
			 * \brief	Move Constructor. Right hand size will be zeroized.
			 *
			 * \param [in,out]	rhs	The right hand side.
			 */
			SecretKeyWrap(SecretKeyWrap&& rhs) :
				m_key(rhs.m_key)
			{
				ZeroizeContainer(rhs.m_key);
			}

			/**
			 * \brief	Assignment operator
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	A reference to this instance.
			 */
			SecretKeyWrap& operator=(const SecretKeyWrap& rhs)
			{
				m_key = rhs.m_key;
				return *this;
			}

			/**
			 * \brief	Move assignment operator
			 *
			 * \param [in,out]	rhs	The right hand side.
			 *
			 * \return	A reference to this instance.
			 */
			SecretKeyWrap& operator=(SecretKeyWrap&& rhs)
			{
				m_key = std::forward<decltype(m_key)>(rhs.m_key);
				if (this != &rhs)
				{
					ZeroizeContainer(rhs.m_key);
				}
				return *this;
			}

			/** \brief	Destructor, which will zeroize the memory of the secret key. */
			~SecretKeyWrap()
			{
				ZeroizeContainer(m_key);
			}
		};
	}
}
