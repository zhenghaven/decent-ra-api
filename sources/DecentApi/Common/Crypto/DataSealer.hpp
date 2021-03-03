#pragma once

//#define ENCLAVE_ENVIRONMENT
//#define ENCLAVE_SGX_ENVIRONMENT

#include <cstring>

#if defined(ENCLAVE_ENVIRONMENT)

#if defined(ENCLAVE_SGX_ENVIRONMENT)
#include <sgx_utils.h>
#include <sgx_attributes.h>

#include "../SGX/ErrorCode.h"
#endif // defined(ENCLAVE_SGX_ENVIRONMENT)

#endif // defined(ENCLAVE_ENVIRONMENT)

#include <mbedTLScpp/SKey.hpp>
#include <mbedTLScpp/Hkdf.hpp>
#include <mbedTLScpp/DefaultRbg.hpp>

#include "../Ra/States.h"
#include "../Ra/WhiteList/LoadedList.h"
#include "../Tools/EnclaveId.hpp"

#include "AesGcmPacker.hpp"

namespace Decent
{
	namespace Crypto
	{
		enum class SealKeyPolicy
		{
			ByMrEnclave,
			ByMrSigner,
			ByMrEnclaveAndMrSigner,
		};

#if defined(ENCLAVE_ENVIRONMENT)

#if defined(ENCLAVE_SGX_ENVIRONMENT)
		namespace Sgx
		{
			//These variables are came from SGX SDK:
			constexpr uint64_t gsk_TSEAL_FLAGS_NON_SECURITY_BITS = (0xFFFFFFFFFFFFC0ULL | SGX_FLAGS_MODE64BIT | SGX_FLAGS_PROVISION_KEY | SGX_FLAGS_EINITTOKEN_KEY);
			constexpr uint64_t gsk_TSEAL_DEFAULT_FLAGSMASK = (~gsk_TSEAL_FLAGS_NON_SECURITY_BITS);

			constexpr uint32_t gsk_TSEAL_MISC_NON_SECURITY_BITS = 0x0FFFFFFFUL;  /* bit[27:0]: have no security implications */
			constexpr uint32_t gsk_TSEAL_DEFAULT_MISCMASK = (~gsk_TSEAL_MISC_NON_SECURITY_BITS);

			/**
			 * \brief	Values that represent SGX key types. Too SGX specific functionalities, and any type
			 * 			other than Seal key is not very useful for now, thus, we don't expose it to the API
			 * 			for now.
			 */
			enum class SealKeyType
			{
				EInitToken,
				Provision,
				ProvisionSeal,
				Report,
				Seal,
			};

			constexpr char const gsk_sgxMetaLabel[] = "SGX";

#pragma pack(push, 1)
			struct SealKeyMeta
			{
				char     m_label [sizeof(gsk_sgxMetaLabel)]; //32-bit
				uint8_t  m_keyId [32];                       //256-bit
				uint8_t  m_CpuSvn[16];                       //128-bit
				uint16_t m_IsvSvn;                           //16-bit
			};
#pragma pack(pop)

			static_assert(sizeof(SealKeyMeta::m_keyId) == sizeof(sgx_key_request_t::key_id),
				"The size of Key ID dosen't match SGX SDK. Probably caused by a SDK update.");
			static_assert(sizeof(SealKeyMeta::m_CpuSvn) == sizeof(sgx_key_request_t::cpu_svn),
				"The size of CPU SVN dosen't match SGX SDK. Probably caused by a SDK update.");
			static_assert(sizeof(SealKeyMeta::m_IsvSvn) == sizeof(sgx_key_request_t::isv_svn),
				"The size of ISV SVN dosen't match SGX SDK. Probably caused by a SDK update.");
			static_assert(sizeof(SealKeyMeta) ==
				(sizeof(SealKeyMeta::m_keyId) + sizeof(SealKeyMeta::m_CpuSvn) +
					sizeof(SealKeyMeta::m_IsvSvn) + sizeof(gsk_sgxMetaLabel)
				),
				"KeyRecoverMeta struct isn't packed, may cause error since current implmentation may rely on it.");

			constexpr uint16_t GetSealKeyName(SealKeyType keyType)
			{
				return (
					keyType == SealKeyType::EInitToken    ? SGX_KEYSELECT_EINITTOKEN     : (
					keyType == SealKeyType::Provision     ? SGX_KEYSELECT_PROVISION      : (
					keyType == SealKeyType::ProvisionSeal ? SGX_KEYSELECT_PROVISION_SEAL : (
					keyType == SealKeyType::Report        ? SGX_KEYSELECT_REPORT         : (
					keyType == SealKeyType::Seal          ? SGX_KEYSELECT_SEAL           : (
					throw Decent::RuntimeException("Decent::Crypto::Sgx::GetSealKeyName - Invalid parameter.")
				))))));
			}

			constexpr uint16_t GetSealKeyPolicy(SealKeyPolicy keyPolicy)
			{
				return (
					keyPolicy == SealKeyPolicy::ByMrEnclave            ? SGX_KEYPOLICY_MRENCLAVE                          : (
					keyPolicy == SealKeyPolicy::ByMrSigner             ? SGX_KEYPOLICY_MRSIGNER                           : (
					keyPolicy == SealKeyPolicy::ByMrEnclaveAndMrSigner ? SGX_KEYPOLICY_MRENCLAVE | SGX_KEYPOLICY_MRSIGNER : (
					throw Decent::RuntimeException("Decent::Crypto::Sgx::GetSealKeyPolicy - Invalid parameter.")
				))));
			}

			inline mbedTLScpp::SKey<128> DeriveSealKey(SealKeyType keyType, SealKeyPolicy keyPolicy, const SealKeyMeta& meta)
			{
				using ByteArray128Bit = uint8_t[16];
				using ByteArray128BitPtr = typename std::add_pointer<ByteArray128Bit>::type;

				if (std::memcmp(meta.m_label, gsk_sgxMetaLabel, sizeof(gsk_sgxMetaLabel)) != 0)
				{
					throw Decent::RuntimeException("Decent::Crypto::Sgx::DeriveSealKey - Invalid metadata is given.");
				}

				sgx_key_request_t keyReq;
				memset(&keyReq, 0, sizeof(sgx_key_request_t));

				keyReq.key_name   = GetSealKeyName(keyType);
				keyReq.key_policy = GetSealKeyPolicy(keyPolicy);

				memcpy(&keyReq.key_id, meta.m_keyId, sizeof(sgx_key_id_t));
				memcpy(&keyReq.cpu_svn, meta.m_CpuSvn, sizeof(sgx_cpu_svn_t));
				memcpy(&keyReq.isv_svn, &meta.m_IsvSvn, sizeof(sgx_isv_svn_t));

				keyReq.attribute_mask.flags = gsk_TSEAL_DEFAULT_FLAGSMASK;
				keyReq.attribute_mask.xfrm = 0x0;
				keyReq.misc_mask = gsk_TSEAL_DEFAULT_MISCMASK;

				mbedTLScpp::SKey<128> outKey;
				ByteArray128BitPtr outKeyPtr = reinterpret_cast<ByteArray128BitPtr>(outKey.data());

				sgx_status_t sgxRet = sgx_get_key(&keyReq, outKeyPtr);
				if (sgxRet != SGX_SUCCESS)
				{
					throw Decent::RuntimeException(Decent::Sgx::ConstructSimpleErrorMsg(sgxRet, "sgx_get_key"));
				}

				return outKey;
			}
		}
#endif // defined(ENCLAVE_SGX_ENVIRONMENT)

		mbedTLScpp::SecretVector<uint8_t> DeriveAppRootSealKey(
			SealKeyPolicy keyPolicy,
			const std::vector<uint8_t>& metaData);

		/**
		 * \brief  Generates a seal key recovery metadata.
		 *         This metadata is necessary anytime when deriving the seal key.
		 *         Moreover, to derive the same seal key that has been used before, the
		 *         metadata with the same content must be used, otherwise, a different key
		 *         will be derived.
		 *         Thus, it's recommended to save the metadata with
		 *         the sealed data.
		 *
		 * \exception	Decent::RuntimeException	Thrown when underlying function call failed.
		 *
		 * \param	isDefault	(Optional) True to generate the metadata with all 'empty' values. It's
		 * 						not recommended to enable this in most of cases.
		 *
		 * \return	The metadata.
		 */
		std::vector<uint8_t> GenSealKeyMeta(bool isDefault = false);

		/**
		 * \brief	Derive Decent seal key
		 *
		 * \exception	Decent::RuntimeException	Thrown when underlying function call failed.
		 *
		 * \tparam	_keySizeInBits 	The size (in bits) of the key to be derived.
		 *
		 * \param 		  	keyPolicy  	The key policy.
		 * \param 		  	decentState	State of the decent.
		 * \param 		  	label	   	The label.
		 * \param 		  	salt	   	The salt.
		 * \param 		  	meta	   	The metadata used to derive the key.
		 *
		 */
		template<size_t _keySizeInBits>
		inline mbedTLScpp::SKey<_keySizeInBits> DeriveDecentSealKey(
			SealKeyPolicy keyPolicy,
			const Ra::States& decentState,
			const std::string& label,
			const std::vector<uint8_t>& salt,
			const std::vector<uint8_t>& metaData
		)
		{
			using namespace mbedTLScpp;

			auto appRootKey = DeriveAppRootSealKey(keyPolicy, metaData);

			return mbedTLScpp::Hkdf<HashType::SHA256, _keySizeInBits>(
				CtnFullR(appRootKey),
				CtnFullR(decentState.GetLoadedWhiteList().GetWhiteListHash() + label),
				CtnFullR(salt)
			);
		}

		template<size_t _keySizeInBits>
		class DataSealer
		{
		public: // static members:

			static constexpr size_t sk_keySizeInBits = _keySizeInBits;

		public:
			DataSealer(
				SealKeyPolicy keyPolicy,
				const Ra::States& decentState,
				const std::string& label,
				const std::vector<uint8_t>& salt,
				const std::vector<uint8_t>& keyMeta = GenSealKeyMeta(false),
				size_t sealedBlockSize = 4096
			) :
				m_keyPolicy(keyPolicy),
				m_keyLabel(label),
				m_keySalt(salt),
				m_keyMeta(keyMeta),
				m_sealKey(DeriveDecentSealKey<_keySizeInBits>(m_keyPolicy, decentState, m_keyLabel, m_keySalt, m_keyMeta)),
				m_gcm(mbedTLScpp::CtnFullR(m_sealKey), sealedBlockSize)
			{}

			~DataSealer()
			{}

			/**
			 * \brief	Seal data
			 *
			 * \exception	Decent::RuntimeException	Thrown when underlying function call failed.
			 *
			 * \tparam	_MetaCtnType	Container type that stores the metadata.
			 * \tparam	_MetaCtnSecrecy	Secrecy of the container type that stores the metadata.
			 * \tparam	_DataCtnType	Container type that stores the data.
			 * \tparam	_DataCtnSecrecy	Secrecy of the container type that stores the data.
			 *
			 * \param 	   	metadata	   	The metadata.
			 * \param 	   	data		   	The data.
			 *
			 * \return	A pair of sealed data, and the AES-GCM tag.
			 */
			template<typename _MetaCtnType, bool _MetaCtnSecrecy,
				typename _DataCtnType, bool _DataCtnSecrecy
			>
			std::pair<std::vector<uint8_t> /* Sealed */, std::array<uint8_t, 16> /* Tag */> Seal(
				const mbedTLScpp::ContCtnReadOnlyRef<_MetaCtnType, _MetaCtnSecrecy>& meta,
				const mbedTLScpp::ContCtnReadOnlyRef<_DataCtnType, _DataCtnSecrecy>& data
			)
			{
				using namespace mbedTLScpp;

				return m_gcm.Pack(
					CtnFullR(m_keyMeta),
					meta,
					data,
					CtnFullR(gsk_emptyCtn)
				);
			}

			/**
			 * \brief	Unseal data
			 *
			 * \exception	Decent::RuntimeException	Thrown when the sealed data structure is invalid, or
			 * 											underlying function call failed.
			 *
			 * \param 	   	inData		   	Input, sealed data.
			 * \param 	   	inTag		   	The input tag. If the pointer is not null, the tag retrieved from
			 * 								the sealed data will be compared with the input tag.
			 *
			 * \return	A pair of unsealed data and meta.
			 */
			std::pair<mbedTLScpp::SecretVector<uint8_t> /* Data */, mbedTLScpp::SecretVector<uint8_t> /* Meta */> Unseal(
				const std::vector<uint8_t>& inData,
				const std::array<uint8_t, 16>* inTag = nullptr)
			{
				using namespace mbedTLScpp;

				return m_gcm.Unpack(
					CtnFullR(inData),
					CtnFullR(gsk_emptyCtn),
					inTag
				);
			}

		private:
			SealKeyPolicy        m_keyPolicy;
			std::string          m_keyLabel;
			std::vector<uint8_t> m_keySalt;
			std::vector<uint8_t> m_keyMeta;
			mbedTLScpp::SKey<_keySizeInBits> m_sealKey;
			AesGcmPacker m_gcm;
		};

#endif // defined(ENCLAVE_ENVIRONMENT)

	}
}


#if defined(ENCLAVE_ENVIRONMENT)

#if defined(ENCLAVE_SGX_ENVIRONMENT)

inline mbedTLScpp::SecretVector<uint8_t> Decent::Crypto::DeriveAppRootSealKey(
	Decent::Crypto::SealKeyPolicy keyPolicy, const std::vector<uint8_t>& metaData
)
{
	using namespace Decent::Crypto;
	using namespace mbedTLScpp;

	if (metaData.size() != sizeof(Sgx::SealKeyMeta))
	{
		throw Decent::RuntimeException("Decent::Crypto::DeriveAppRootSealKey - Invalid metadata.");
	}
	const Sgx::SealKeyMeta& metaRef = *reinterpret_cast<const Sgx::SealKeyMeta*>(metaData.data());

	auto keyArray = Sgx::DeriveSealKey(Sgx::SealKeyType::Seal, keyPolicy, metaRef);

	mbedTLScpp::SecretVector<uint8_t> outKey(keyArray.begin(), keyArray.end());

	return outKey;
}

inline std::vector<uint8_t> Decent::Crypto::GenSealKeyMeta(bool isDefault)
{
	using namespace Decent::Crypto;
	using namespace mbedTLScpp;

	std::vector<uint8_t> res(sizeof(Sgx::SealKeyMeta), 0);
	Sgx::SealKeyMeta& metaRef = *reinterpret_cast<Sgx::SealKeyMeta*>(res.data());

	std::memcpy(metaRef.m_label, Sgx::gsk_sgxMetaLabel, sizeof(Sgx::gsk_sgxMetaLabel));

	if (isDefault)
	{
		return res;
	}

	DefaultRbg().Rand(metaRef.m_keyId, sizeof(Sgx::SealKeyMeta::m_keyId));

	std::memcpy(metaRef.m_CpuSvn, Tools::Sgx::GetSelfReport().body.cpu_svn.svn, sizeof(Sgx::SealKeyMeta::m_CpuSvn));
	metaRef.m_IsvSvn = Tools::Sgx::GetSelfReport().body.isv_svn;

	return res;
}

#else
#error "DeriveAppRootSealKey - The implementation for this enclave platform is missing."
#endif // defined(ENCLAVE_SGX_ENVIRONMENT)

#endif // defined(ENCLAVE_ENVIRONMENT)

