#pragma once

#include <cstdint>

#include <string>
#include <vector>

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
				//std::vector<uint8_t> PlatformDeriveSealKey(KeyPolicy keyPolicy, const std::vector<uint8_t>& meta);

				void DeriveSealKey(KeyPolicy keyPolicy, const Ra::States& decentState, const std::string& label, 
					void* outKey, const size_t expectedKeySize, const void* inMeta, const size_t inMetaSize, const std::vector<uint8_t>& salt);

				std::vector<uint8_t> SealData(KeyPolicy keyPolicy, const Ra::States& decentState, const std::string& keyLabel, 
					std::vector<uint8_t>& outMac, const void* inMetadata, const size_t inMetadataSize, const void* inData, const size_t inDataSize);

				void UnsealData(KeyPolicy keyPolicy, const Ra::States& decentState, const std::string& keyLabel, 
					const void* inEncData, const size_t inEncDataSize, const std::vector<uint8_t>& inMac, std::vector<uint8_t>& outMeta, std::vector<uint8_t>& outData);
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
				detail::DeriveSealKey(keyPolicy, decentState, label, ArrayPtrAndSize::GetPtr(outKey), ArrayPtrAndSize::GetSize(outKey), 
					ArrayPtrAndSize::GetPtr(meta), ArrayPtrAndSize::GetSize(meta), salt);
			}

			/**
			 * \brief	Seal data
			 *
			 * \tparam	MetaCtn	Container type that stores the metadata.
			 * \tparam	DataCtn	Container type that stores the data.
			 * \param 	   	keyPolicy	The key policy.
			 * \param [out]	outMac   	The output MAC. The MAC generated when sealing the data. This can be
			 * 							used to prevent replay attack during unseal process.
			 * \param 	   	metadata 	The metadata.
			 * \param 	   	data	 	The data.
			 *
			 * \return	A std::vector&lt;uint8_t&gt;, the sealed data.
			 */
			template<typename MetaCtn, typename DataCtn>
			std::vector<uint8_t> SealData(KeyPolicy keyPolicy, const Ra::States& decentState, const std::string& keyLabel, 
				std::vector<uint8_t>& outMac, const MetaCtn& metadata, const DataCtn& data)
			{
				return detail::SealData(keyPolicy, decentState, keyLabel, outMac, 
					ArrayPtrAndSize::GetPtr(metadata), ArrayPtrAndSize::GetSize(metadata),
					ArrayPtrAndSize::GetPtr(data), ArrayPtrAndSize::GetSize(data));
			}

			/**
			 * \brief	Unseal data
			 *
			 * \tparam	SealedDataCtn	Container type that stores the sealed data .
			 * \param 	   	keyPolicy	The key policy.
			 * \param 	   	inData   	Input, sealed data.
			 * \param 	   	inMac	 	The input MAC. If the size of the container is greater than zero, the
			 * 							MAC retrieved from the sealed data will be compared with the input
			 * 							MAC.
			 * \param [out]	metadata 	The metadata.
			 * \param [out]	data	 	The data.
			 */
			template<typename SealedDataCtn>
			void UnsealData(KeyPolicy keyPolicy, const Ra::States& decentState, const std::string& keyLabel, 
				const SealedDataCtn& inData, const std::vector<uint8_t>& inMac, std::vector<uint8_t>& metadata, std::vector<uint8_t>& data)
			{
				detail::UnsealData(keyPolicy, decentState, keyLabel, 
					ArrayPtrAndSize::GetPtr(inData), ArrayPtrAndSize::GetSize(inData), inMac, 
					metadata, data);
			}
		}
	}
}
