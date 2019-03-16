#pragma once

#include <array>
#include <string>

#include "MbedTlsCppDefs.h"

namespace Decent
{
	namespace MbedTlsObj
	{
		namespace detail
		{
			/**
			 * \brief	Hash-based Key Derivation Function (HKDF).
			 *
			 * \param 		  	hashType 	Type of the hash.
			 * \param 		  	inKey	 	The input key.
			 * \param 		  	inKeyLen 	Length of the input key.
			 * \param 		  	label	 	The label.
			 * \param 		  	labelLen 	Length of the label.
			 * \param 		  	inSalt   	The input salt.
			 * \param 		  	inSaltLen	Length of the input salt.
			 * \param [in,out]	outKey   	The output key.
			 * \param 		  	outKeyLen	Length of the output key.
			 */
			void HKDF(HashType hashType, const void* inKey, size_t inKeyLen, const void* label, size_t labelLen, const void* inSalt, size_t inSaltLen, void* outKey, size_t outKeyLen);
		}

		/**
		 * \brief	Hash-based Key Derivation Function (HKDF). Input data are in structs.
		 *
		 * \tparam	hashType	Type of the hash algorithm.
		 * \tparam	KeyT		Data type of the key.
		 * \tparam	SaltT   	Data type of the salt.
		 * \tparam	KeyT		Data type of the key.
		 * \param 		  	inKey 	The input key.
		 * \param 		  	label 	The label.
		 * \param 		  	salt  	The salt.
		 * \param [in,out]	outKey	The output key.
		 */
		template<HashType hashType, typename InKeyT, typename SaltT, typename OutKeyT>
		void HKDFStruct(const InKeyT& inKey, const std::string& label, const SaltT& salt, OutKeyT& outKey)
		{
			detail::HKDF(hashType, &inKey, sizeof(inKey), label.c_str(), label.size(), &salt, sizeof(salt), &outKey, sizeof(outKey));
		}

		/**
		 * \brief	Hash-based Key Derivation Function (HKDF).
		 *
		 * \tparam	hashType	Type of the hash algorithm.
		 * \tparam	KeyT		Data type of the key.
		 * \tparam	SaltT   	Data type of the salt.
		 * \param 		  	inKey	 	The input key.
		 * \param 		  	label	 	The label.
		 * \param 		  	salt	 	The salt.
		 * \param [in,out]	outKey   	The output key.
		 * \param 		  	outKeyLen	Length of the output key.
		 */
		template<HashType hashType, typename InKeyT, typename SaltT>
		void HKDF(const InKeyT& inKey, const std::string& label, const SaltT& salt, void* outKey, size_t outKeyLen)
		{
			detail::HKDF(hashType, detail::GetPtr(inKey), detail::GetSize(inKey), label.c_str(), label.size(), detail::GetPtr(salt), detail::GetSize(salt), outKey, outKeyLen);
		}

		/**
		 * \brief	Hash-based Key Derivation Function (HKDF).
		 *
		 * \tparam	hashType	Type of the hash algorithm.
		 * \tparam	KeyT		Data type of the key.
		 * \tparam	SaltT   	Data type of the salt.
		 * \tparam	KeyT		Data type of the key.
		 * \param 		  	inKey 	The input key.
		 * \param 		  	label 	The label.
		 * \param 		  	salt  	The salt.
		 * \param [in,out]	outKey	The output key.
		 */
		template<HashType hashType, typename InKeyT, typename SaltT, typename OutKeyT>
		void HKDF(const InKeyT& inKey, const std::string& label, const SaltT& salt, OutKeyT& outKey)
		{
			detail::HKDF(hashType, detail::GetPtr(inKey), detail::GetSize(inKey), label.c_str(), label.size(), detail::GetPtr(salt), detail::GetSize(salt), detail::GetPtr(outKey), detail::GetSize(outKey));
		}
	}
}
