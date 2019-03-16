#pragma once

#include <cstdint>

#include <string>
#include <vector>

#include "../../Common/GeneralKeyTypes.h"
#include "../../Common/ArrayPtrAndSize.h"

namespace Decent
{
	namespace Tools
	{
		enum class KeyPolicy
		{
			ByMrEnclave,
			ByMrSigner,
			ByMrEnclaveAndMrSigner,
		};

		namespace detail
		{
			void DeriveSealKey(KeyPolicy keyPolicy, const std::string& label, void* outKey, size_t outKeySize, const std::vector<uint8_t>& meta);
		}

		/**
		 * \brief	Derive seal key
		 *
		 * \exception	Decent::RuntimeException	Thrown when underlying function call failed.
		 *
		 * \tparam	KeyT	Data Type that holds the key.
		 * \param 		  	keyPolicy	The key policy.
		 * \param 		  	label	 	The label.
		 * \param [in,out]	outKey   	The output key.
		 * \param 		  	meta	 	The metadata used to derive the key.
		 */
		template<typename KeyT>
		void DeriveSealKey(KeyPolicy keyPolicy, const std::string& label, KeyT& outKey, const std::vector<uint8_t>& meta)
		{
			detail::DeriveSealKey(keyPolicy, label, ArrayPtrAndSize::GetPtr(outKey), ArrayPtrAndSize::GetSize(outKey), meta);
		}

		/**
		 * \brief	Generates a seal key recovery metadata
		 *
		 * \exception	Decent::RuntimeException	Thrown when underlying function call failed.
		 *
		 * \param [in,out]	outMeta	The output metadata.
		 */
		void GenSealKeyRecoverMeta(std::vector<uint8_t>& outMeta);

		/**
		 * \brief	Gets self hash in Base64 encoding.
		 *
		 * \exception	Decent::RuntimeException	Thrown when underlying function call failed.
		 *
		 * \return	The Base64 encoding string.
		 */
		const std::string& GetSelfHashBase64();

		/**
		 * \brief	Gets self hash in binary.
		 *
		 * \exception	Decent::RuntimeException	Thrown when underlying function call failed.
		 *
		 * \return	A binary array.
		 */
		const std::vector<uint8_t>& GetSelfHash();
	}
}
