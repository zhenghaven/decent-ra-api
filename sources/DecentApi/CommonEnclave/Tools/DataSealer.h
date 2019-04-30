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
		namespace DataSealer
		{
			enum class KeyPolicy
			{
				ByMrEnclave,
				ByMrSigner,
				ByMrEnclaveAndMrSigner,
			};

			namespace detail
			{
				/**
				 * \brief	This function calls platform seal key derivation function. Its implementation is
				 * 			determined by the platform. Note: this function derive the root seal for this enclave
				 * 			program or signer (or both), thus, it's not recommended to use this function
				 * 			directly. Instead, use the following functions to derive different seal keys for
				 * 			different functionalities.
				 *
				 * \param	keyPolicy	The key policy.
				 * \param	meta	 	The meta.
				 *
				 * \return	A std::vector&lt;uint8_t&gt;
				 */
				std::vector<uint8_t> PlatformDeriveSealKey(KeyPolicy keyPolicy, const std::vector<uint8_t>& meta);

				void DeriveSealKey(KeyPolicy keyPolicy, const std::string& label, void* outKey, size_t outKeySize, const std::vector<uint8_t>& salt, const std::vector<uint8_t>& meta);
			}

			/**
			 * \brief	Generates a seal key recovery metadata. This metadata is necessary when deriving the
			 * 			seal key. Moreover, to derive the same seal key that has been used before, the
			 * 			metadata must be the same as well. Thus, it's recommended to save the metadata with
			 * 			the sealed data.
			 *
			 * \exception	Decent::RuntimeException	Thrown when underlying function call failed.
			 *
			 * \param	isDefault	(Optional) True to generate the metadata with all 'empty' values. It's
			 * 						not recommended to enable this in most of cases.
			 *
			 * \return	The metadata.
			 */
			std::vector<uint8_t> GenSealKeyRecoverMeta(bool isDefault = false);

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
			void DeriveSealKey(KeyPolicy keyPolicy, const std::string& label, KeyT& outKey, const std::vector<uint8_t>& salt, const std::vector<uint8_t>& meta)
			{
				detail::DeriveSealKey(keyPolicy, label, ArrayPtrAndSize::GetPtr(outKey), ArrayPtrAndSize::GetSize(outKey), salt, meta);
			}
		}
	}
}
