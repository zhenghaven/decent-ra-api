#pragma once

#include <memory>
#include <string>
#include <type_traits>
#ifdef DECENT_THREAD_SAFETY_HIGH
#include <atomic>
#endif // DECENT_THREAD_SAFETY_HIGH

#include <mbedTLScpp/EcKey.hpp>

#include "../general_key_types.h"

namespace Decent
{
	namespace Ra
	{
		class KeyContainer
		{
		public: // Static members:

			using KeyTypeInCpp = mbedTLScpp::EcKeyPair<mbedTLScpp::EcType::SECP256R1>;

		public:
			KeyContainer();

			KeyContainer(const general_secp256r1_public_t& pubKey, const general_secp256r1_private_t& prvKey) :
				m_signPrvKeyObj(
					std::make_shared<KeyTypeInCpp>(
						KeyTypeInCpp::FromBytes(
							CtnFullR(KeyTypeInCpp::KSecArray(prvKey.r)), mbedTLScpp::CtnFullR(pubKey.x), mbedTLScpp::CtnFullR(pubKey.y)
						)
					)
				)
			{}

			KeyContainer(const general_secp256r1_private_t& prvKey) :
				m_signPrvKeyObj(
					std::make_shared<KeyTypeInCpp>(
						KeyTypeInCpp::FromBytes(CtnFullR(KeyTypeInCpp::KSecArray(prvKey.r)))
					)
				)
			{}

			KeyContainer(std::unique_ptr<KeyTypeInCpp> keyPair) :
				m_signPrvKeyObj(std::move(keyPair))
			{}

			virtual ~KeyContainer()
			{}

			virtual std::shared_ptr<const KeyTypeInCpp> GetSignKeyPair() const
			{
				return DataGetter(m_signPrvKeyObj);
			}

		protected: // Static members:

			template<typename _KeyType>
			static std::shared_ptr<typename std::add_const<_KeyType>::type> DataGetter(
				const std::shared_ptr<_KeyType>& data)
			{
#ifdef DECENT_THREAD_SAFETY_HIGH
				return std::atomic_load(&data);
#else
				return data;
#endif // DECENT_THREAD_SAFETY_HIGH
			}

			template<typename _KeyType>
			static void DataSetter(std::shared_ptr<_KeyType>& data, std::shared_ptr<_KeyType> input)
			{
#ifdef DECENT_THREAD_SAFETY_HIGH
				std::atomic_store(&data, input);
#else
				data = input;
#endif // DECENT_THREAD_SAFETY_HIGH
			}

		protected:

			virtual void SetSignKeyPair(std::shared_ptr<KeyTypeInCpp> key)
			{
				DataSetter(m_signPrvKeyObj, key);
			}

		private:
			std::shared_ptr<KeyTypeInCpp> m_signPrvKeyObj;
		};
	}
}
