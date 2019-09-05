#pragma once

#include <array>
#include <string>

#include "MbedTlsCppDefs.h"
#include "MACer.h"

namespace Decent
{
	namespace MbedTlsObj
	{
		namespace detail
		{
			/**
			 * \brief	Hash-based Key Derivation Function (HKDF).
			 *
			 * \param 		  	hashType	  	Type of the hash.
			 * \param 		  	inKey		  	The input key.
			 * \param 		  	inKeyLen	  	Length of the input key.
			 * \param 		  	label		  	The label.
			 * \param 		  	labelLen	  	Length of the label.
			 * \param 		  	inSalt		  	The input salt (optional).
			 * \param 		  	inSaltLen	  	Length of the input salt.
			 * \param [in,out]	outKey		  	The output key.
			 * \param 		  	expectedKeyLen	Length of the output key that is wanted.
			 */
			void HKDF(HashType hashType, const void* inKey, const size_t inKeyLen, const void* label, const size_t labelLen, const void* inSalt, const size_t inSaltLen, void* outKey, const size_t expectedKeyLen);

			std::vector<uint8_t> GetCkdfByteSequence(const uint8_t ctr, const std::string& label, const uint16_t resKeyBitSize);
		}

		/**
		 * \brief	Hash-based Key Derivation Function (HKDF). Input data are in structs. Note: size of
		 * 			the outKey is the size of the key you want.
		 *
		 * \tparam	hashType	Type of the hash algorithm.
		 * \tparam	KeyT		Data type of the key.
		 * \tparam	SaltT   	Data type of the salt.
		 * \tparam	KeyT		Data type of the key.
		 * \param 		  	inKey 	The input key.
		 * \param 		  	label 	The label.
		 * \param 		  	salt  	The salt (optional).
		 * \param [in,out]	outKey	The output key. Note: size of the outKey is the size of the key you
		 * 							want.
		 */
		template<HashType hashType, typename InKeyT, typename SaltT, typename OutKeyT>
		inline void HKDFStruct(const InKeyT& inKey, const std::string& label, const SaltT& salt, OutKeyT& outKey)
		{
			detail::HKDF(hashType, &inKey, sizeof(inKey), label.c_str(), label.size(), &salt, sizeof(salt), &outKey, sizeof(outKey));
		}

		/**
		 * \brief	Hash-based Key Derivation Function (HKDF).
		 *
		 * \tparam	hashType	Type of the hash algorithm.
		 * \tparam	KeyT		Data type of the key.
		 * \tparam	SaltT   	Data type of the salt.
		 * \param 		  	inKey		  	The input key.
		 * \param 		  	label		  	The label.
		 * \param 		  	salt		  	The salt (optional).
		 * \param [in,out]	outKey		  	The output key.
		 * \param 		  	expectedKeyLen	Length of the output key that is wanted.
		 */
		template<HashType hashType, typename InKeyT, typename SaltT>
		inline void HKDF(const InKeyT& inKey, const std::string& label, const SaltT& salt, void* outKey, const size_t expectedKeyLen)
		{
			detail::HKDF(hashType, detail::GetPtr(inKey), detail::GetSize(inKey), label.c_str(), label.size(), detail::GetPtr(salt), detail::GetSize(salt), outKey, expectedKeyLen);
		}

		/**
		 * \brief	Hash-based Key Derivation Function (HKDF). Note: size of the outKey is the size of
		 * 			the key you want.
		 *
		 * \tparam	hashType	Type of the hash algorithm.
		 * \tparam	KeyT		Data type of the key.
		 * \tparam	SaltT   	Data type of the salt.
		 * \tparam	KeyT		Data type of the key.
		 * \param 		  	inKey 	The input key.
		 * \param 		  	label 	The label.
		 * \param 		  	salt  	The salt (optional).
		 * \param [in,out]	outKey	The output key. Note: size of the outKey is the size of the key you
		 * 							want.
		 */
		template<HashType hashType, typename InKeyT, typename SaltT, typename OutKeyT>
		inline void HKDF(const InKeyT& inKey, const std::string& label, const SaltT& salt, OutKeyT& outKey)
		{
			detail::HKDF(hashType, detail::GetPtr(inKey), detail::GetSize(inKey), label.c_str(), label.size(), detail::GetPtr(salt), detail::GetSize(salt), detail::GetPtr(outKey), detail::GetSize(outKey));
		}

		/**
		 * \brief	Cipher-based Key Derivation Function (CKDF). Based on the the key derivation function
		 * 			used in SGX RA.
		 *
		 * \tparam	cType	  	Type of the cipher.
		 * \tparam	cSize	  	Type of the cipher. In Bytes.
		 * \tparam	cMode	  	Mode of the cipher.
		 * \tparam	oriKeySize	Size of the input key. In Bytes.
		 * \param 	   	inKey 	The input key.
		 * \param 	   	label 	The label.
		 * \param [out]	outKey	The output key.
		 */
		template<CipherType cType, uint16_t cSize, CipherMode cMode, size_t oriKeySize>
		inline void CKDF(const SecretKeyWrap<oriKeySize>& inKey, const std::string& label, SecretKeyWrap<cSize>& outKey)
		{
			SecretKeyWrap<cSize> cmacKey;
			SecretKeyWrap<cSize> deriveKey;
			CMACer<cType, cSize, cMode>(cmacKey).Calc(deriveKey.m_key, inKey.m_key);

			CMACer<cType, cSize, cMode>(deriveKey).Calc(outKey.m_key, detail::GetCkdfByteSequence(0x01, label, cSize));
		}
	}
}
