#pragma once

#include <memory>

//#define ENCLAVE_ENVIRONMENT
//#define ENCLAVE_SGX_ENVIRONMENT
#if defined(ENCLAVE_ENVIRONMENT) && defined(ENCLAVE_SGX_ENVIRONMENT)
#include <sgx_tcrypto.h>
#include "../SGX/RuntimeError.h"
#endif

#include <mbedTLScpp/Gcm.hpp>

namespace Decent
{
	namespace Crypto
	{
		class SoftAesGcm
		{
		public:
			template<typename _SecCtnType>
			SoftAesGcm(const mbedTLScpp::ContCtnReadOnlyRef<_SecCtnType, true>& key) :
				m_gcm(key, mbedTLScpp::CipherType::AES)
			{}

			~SoftAesGcm()
			{}

			SoftAesGcm(SoftAesGcm&& rhs) noexcept :
				m_gcm(std::move(rhs.m_gcm)) //noexcept
			{}

			SoftAesGcm(const SoftAesGcm& rhs) = delete;

			template<typename _DataCtnType, bool _DataSec,
				typename _IvCtnType, bool _IvSec,
				typename _AddCtnType, bool _AddSec>
				std::pair<std::vector<uint8_t>, std::array<uint8_t, 16> > Encrypt(
					const mbedTLScpp::ContCtnReadOnlyRef<_DataCtnType, _DataSec>& data,
					const mbedTLScpp::ContCtnReadOnlyRef<_IvCtnType,   _IvSec  >& iv,
					const mbedTLScpp::ContCtnReadOnlyRef<_AddCtnType,  _AddSec >& add)
			{
				return m_gcm.Encrypt(data, iv, add);
			}

			template<typename _DataCtnType, bool _DataSec,
				typename _IvCtnType, bool _IvSec,
				typename _AddCtnType, bool _AddSec,
				typename _TagCtnType>
				mbedTLScpp::SecretVector<uint8_t> Decrypt(
					const mbedTLScpp::ContCtnReadOnlyRef<_DataCtnType, _DataSec>& data,
					const mbedTLScpp::ContCtnReadOnlyRef<_IvCtnType,   _IvSec  >& iv,
					const mbedTLScpp::ContCtnReadOnlyRef<_AddCtnType,  _AddSec >& add,
					const mbedTLScpp::ContCtnReadOnlyRef<_TagCtnType,  false   >& tag)
			{
				return m_gcm.Decrypt(data, iv, add, tag);
			}

		private:
			mbedTLScpp::GcmBase<> m_gcm;
		};

		class EnclaveAesGcm
		{
		public:
			template<typename _SecCtnType>
			EnclaveAesGcm(const mbedTLScpp::ContCtnReadOnlyRef<_SecCtnType, true>& key) :
				m_gcm(),
				m_skey(key.BeginBytePtr(), key.EndBytePtr())
			{}

			~EnclaveAesGcm()
			{}

			EnclaveAesGcm(EnclaveAesGcm&& rhs) noexcept :
				m_gcm(std::move(rhs.m_gcm)), //noexcept
				m_skey(std::move(rhs.m_skey)) //noexcept
			{}

			EnclaveAesGcm(const EnclaveAesGcm& rhs) = delete;

			template<typename _DataCtnType, bool _DataSec,
				typename _IvCtnType, bool _IvSec,
				typename _AddCtnType, bool _AddSec>
				std::pair<std::vector<uint8_t>, std::array<uint8_t, 16> > SoftEncrypt(
					const mbedTLScpp::ContCtnReadOnlyRef<_DataCtnType, _DataSec>& data,
					const mbedTLScpp::ContCtnReadOnlyRef<_IvCtnType,   _IvSec  >& iv,
					const mbedTLScpp::ContCtnReadOnlyRef<_AddCtnType,  _AddSec >& add)
			{
				return m_gcm->Encrypt(data, iv, add);
			}

			template<typename _DataCtnType, bool _DataSec,
				typename _IvCtnType, bool _IvSec,
				typename _AddCtnType, bool _AddSec,
				typename _TagCtnType>
				mbedTLScpp::SecretVector<uint8_t> SoftDecrypt(
					const mbedTLScpp::ContCtnReadOnlyRef<_DataCtnType, _DataSec>& data,
					const mbedTLScpp::ContCtnReadOnlyRef<_IvCtnType,   _IvSec  >& iv,
					const mbedTLScpp::ContCtnReadOnlyRef<_AddCtnType,  _AddSec >& add,
					const mbedTLScpp::ContCtnReadOnlyRef<_TagCtnType,  false   >& tag)
			{
				return m_gcm->Decrypt(data, iv, add, tag);
			}

			template<typename _DataCtnType, bool _DataSec,
				typename _IvCtnType, bool _IvSec,
				typename _AddCtnType, bool _AddSec>
				std::pair<std::vector<uint8_t>, std::array<uint8_t, 16> > Encrypt(
					const mbedTLScpp::ContCtnReadOnlyRef<_DataCtnType, _DataSec>& data,
					const mbedTLScpp::ContCtnReadOnlyRef<_IvCtnType,   _IvSec  >& iv,
					const mbedTLScpp::ContCtnReadOnlyRef<_AddCtnType,  _AddSec >& add)
#if defined(ENCLAVE_ENVIRONMENT) && defined(ENCLAVE_SGX_ENVIRONMENT)
			{
				using namespace mbedTLScpp;

				if (m_skey.size() != sizeof(sgx_aes_gcm_128bit_key_t))
				{
					if (m_gcm == nullptr)
					{
						m_gcm = Internal::make_unique<GcmBase<> >(
							CtnFullR(m_skey), CipherType::AES
						);
					}

					return m_gcm->Encrypt(data, iv, add);
				}
				else
				{
					using ConstKeyArray = const uint8_t[sizeof(sgx_aes_gcm_128bit_key_t)];
					using ConstKeyArrayPtr = std::add_pointer<typename ConstKeyArray>::type;

					using TagArray = uint8_t[sizeof(sgx_aes_gcm_128bit_tag_t)];
					using TagArrayPtr = std::add_pointer<typename TagArray>::type;

					std::vector<uint8_t> cipher(data.GetRegionSize());
					std::array<uint8_t, 16> tag;

					ConstKeyArrayPtr keyPtr = reinterpret_cast<ConstKeyArrayPtr>(m_skey.data());
					TagArrayPtr      tagPtr = reinterpret_cast<TagArrayPtr>(tag.data());

					sgx_status_t sgxRet = sgx_rijndael128GCM_encrypt(keyPtr,
						data.BeginBytePtr(), static_cast<uint32_t>(data.GetRegionSize()),
						cipher.data(),
						iv.BeginBytePtr(),   static_cast<uint32_t>(iv.GetRegionSize()),
						add.BeginBytePtr(),  static_cast<uint32_t>(add.GetRegionSize()),
						tagPtr);
					if (sgxRet != SGX_SUCCESS)
					{
						throw RuntimeException(Decent::Sgx::ConstructSimpleErrorMsg(sgxRet, "sgx_rijndael128GCM_encrypt"));
					}

					return std::make_pair(cipher, tag);
				}
			}
#else
				;
#endif

			template<typename _DataCtnType, bool _DataSec,
				typename _IvCtnType, bool _IvSec,
				typename _AddCtnType, bool _AddSec,
				typename _TagCtnType>
				mbedTLScpp::SecretVector<uint8_t> Decrypt(
					const mbedTLScpp::ContCtnReadOnlyRef<_DataCtnType, _DataSec>& data,
					const mbedTLScpp::ContCtnReadOnlyRef<_IvCtnType, _IvSec  >& iv,
					const mbedTLScpp::ContCtnReadOnlyRef<_AddCtnType, _AddSec >& add,
					const mbedTLScpp::ContCtnReadOnlyRef<_TagCtnType, false   >& tag)
#if defined(ENCLAVE_ENVIRONMENT) && defined(ENCLAVE_SGX_ENVIRONMENT)
			{
				using namespace mbedTLScpp;

				if (m_skey.size() != sizeof(sgx_aes_gcm_128bit_key_t))
				{
					if (m_gcm == nullptr)
					{
						m_gcm = Internal::make_unique<GcmBase<> >(
							CtnFullR(m_skey), CipherType::AES
							);
					}

					return m_gcm->Decrypt(data, iv, add, tag);
				}
				else
				{
					using ConstKeyArray = const uint8_t[sizeof(sgx_aes_gcm_128bit_key_t)];
					using ConstKeyArrayPtr = std::add_pointer<typename ConstKeyArray>::type;

					using ConstTagArray = const uint8_t[sizeof(sgx_aes_gcm_128bit_tag_t)];
					using ConstTagArrayPtr = std::add_pointer<typename ConstTagArray>::type;

					mbedTLScpp::SecretVector<uint8_t> plain(data.GetRegionSize());

					ConstKeyArrayPtr keyPtr = reinterpret_cast<ConstKeyArrayPtr>(m_skey.data());
					ConstTagArrayPtr tagPtr = reinterpret_cast<ConstTagArrayPtr>(tag.BeginPtr());

					sgx_status_t sgxRet = sgx_rijndael128GCM_decrypt(keyPtr,
						data.BeginBytePtr(), static_cast<uint32_t>(data.GetRegionSize()),
						plain.data(),
						iv.BeginBytePtr(),   static_cast<uint32_t>(iv.GetRegionSize()),
						add.BeginBytePtr(),  static_cast<uint32_t>(add.GetRegionSize()),
						tagPtr);
					if (sgxRet != SGX_SUCCESS)
					{
						throw RuntimeException(Decent::Sgx::ConstructSimpleErrorMsg(sgxRet, "sgx_rijndael128GCM_encrypt"));
					}

					return plain;
				}
			}
#else
				;
#endif

		private:
			std::unique_ptr<mbedTLScpp::GcmBase<> > m_gcm;
			mbedTLScpp::SecretVector<uint8_t> m_skey;
		};

#ifdef ENCLAVE_ENVIRONMENT
		using PlatformAesGcm = EnclaveAesGcm;
#else
		using PlatformAesGcm = SoftAesGcm;
#endif // ENCLAVE_ENVIRONMENT

	}
}
