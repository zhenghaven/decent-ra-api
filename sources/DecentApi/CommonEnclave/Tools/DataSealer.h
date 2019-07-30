#pragma once

#include <cstdint>

#include <string>
#include <vector>

#include "../../Common/Tools/Crypto.h"
#include "../../Common/GeneralKeyTypes.h"
#include "../../Common/ArrayPtrAndSize.h"

namespace Decent
{
	namespace Ra
	{
		class States;
	}

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
				void DeriveSealKey(KeyPolicy keyPolicy, const Ra::States& decentState, const std::string& label, 
					void* outKey, const size_t expectedKeySize, const void* inMeta, const size_t inMetaSize, const std::vector<uint8_t>& salt);
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
			 * \tparam	KeyType 	Data Type that holds the key.
			 * \tparam	MetaType	Data Type that holds the metadata.
			 * \param 		  	keyPolicy  	The key policy.
			 * \param 		  	decentState	State of the decent.
			 * \param 		  	label	   	The label.
			 * \param [out]	outKey	   	The output key.
			 * \param 		  	meta	   	The metadata used to derive the key.
			 * \param 		  	salt	   	The salt.
			 *
			 */
			template<typename KeyType, typename MetaType>
			void DeriveSealKey(KeyPolicy keyPolicy, const Ra::States& decentState, const std::string& label, KeyType& outKey, const MetaType& meta, const std::vector<uint8_t>& salt)
			{
				using namespace ArrayPtrAndSize;
				detail::DeriveSealKey(keyPolicy, decentState, label,
					GetPtr(outKey), GetSize(outKey),
					GetPtr(meta), GetSize(meta), salt);
			}

			/**
			 * \brief	Seal data
			 *
			 * \exception	Decent::RuntimeException	Thrown when underlying function call failed.
			 *
			 * \tparam	MetaCtn	Container type that stores the metadata.
			 * \tparam	DataCtn	Container type that stores the data.
			 * \param 	   	keyPolicy	   	The key policy.
			 * \param 	   	decentState	   	Decent global state.
			 * \param 	   	keyLabel	   	The key label.
			 * \param [out]	outTag		   	The output tag. The tag generated when sealing the data. This can
			 * 								be used to prevent replay attack during unseal process.
			 * \param 	   	metadata	   	The metadata.
			 * \param 	   	data		   	The data.
			 * \param 	   	sealedBlockSize	(Optional) Size of the blocks for sealed data. The default size
			 * 								is 4KB.
			 *
			 * \return	A std::vector&lt;uint8_t&gt;, the sealed data.
			 */
			template<typename MetaCtn, typename DataCtn>
			std::vector<uint8_t> SealData(KeyPolicy keyPolicy, const Ra::States& decentState, const std::string& keyLabel, 
				const MetaCtn& metadata, const DataCtn& data, General128Tag& outTag, const size_t sealedBlockSize = 4096)
			{
				std::vector<uint8_t> keyMeta = GenSealKeyRecoverMeta(false);
				General128BitKey sealKey;
				DeriveSealKey(keyPolicy, decentState, keyLabel, sealKey, keyMeta, std::vector<uint8_t>());

				return QuickAesGcmPack(sealKey, keyMeta, metadata, data, outTag, sealedBlockSize);
			}

			/**
			 * \brief	Unseal data
			 *
			 * \exception	Decent::RuntimeException	Thrown when the sealed data structure is invalid, or
			 * 											underlying function call failed.
			 *
			 * \tparam	SealedDataCtn	Container type that stores the sealed data .
			 * \param 	   	keyPolicy	   	The key policy.
			 * \param 	   	decentState	   	Decent global state.
			 * \param 	   	keyLabel	   	The key label.
			 * \param 	   	inData		   	Input, sealed data.
			 * \param 	   	inTag		   	The input tag. If the pointer is not null, the tag retrieved from
			 * 								the sealed data will be compared with the input tag.
			 * \param [out]	metadata	   	The metadata.
			 * \param [out]	data		   	The data.
			 * \param 	   	sealedBlockSize	(Optional) Size of the blocks for sealed data. The default size
			 * 								is 4KB.
			 */
			template<typename SealedDataCtn>
			void UnsealData(KeyPolicy keyPolicy, const Ra::States& decentState, const std::string& keyLabel, 
				const SealedDataCtn& inData, std::vector<uint8_t>& metadata, std::vector<uint8_t>& data, const General128Tag* inTag, const size_t sealedBlockSize = 4096)
			{
				General128BitKey sealKey;
				DeriveSealKey(keyPolicy, decentState, keyLabel, sealKey, GetKeyMetaFromPack(inData), std::vector<uint8_t>());

				return QuickAesGcmUnpack(sealKey, inData, metadata, data, inTag, sealedBlockSize);
			}
		}
	}
}
