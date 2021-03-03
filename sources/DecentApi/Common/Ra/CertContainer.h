#pragma once

#include <memory>

#ifdef DECENT_THREAD_SAFETY_HIGH
#include <atomic>
#endif // DECENT_THREAD_SAFETY_HIGH

#include <mbedTLScpp/X509Cert.hpp>

#include "../Common.h"

namespace Decent
{
	namespace Ra
	{
		class CertContainer
		{
		public:
			CertContainer() = default;

			virtual ~CertContainer()
			{}

			std::shared_ptr<const mbedTLScpp::X509Cert> GetCert() const noexcept
			{
				return DataGetter(m_cert);
			}

			void SetCert(std::shared_ptr<const mbedTLScpp::X509Cert> cert) noexcept
			{
				DataSetter(m_cert, cert);

				LOGI("Saved Cert: \n %s \n", cert->GetPemChain().c_str());
			}

		protected: // Static members:

			template<typename _CertType>
			static std::shared_ptr<typename std::add_const<_CertType>::type> DataGetter(
				const std::shared_ptr<_CertType>& data)
			{
#ifdef DECENT_THREAD_SAFETY_HIGH
				return std::atomic_load(&data);
#else
				return data;
#endif // DECENT_THREAD_SAFETY_HIGH
			}

			template<typename _CertType>
			static void DataSetter(std::shared_ptr<_CertType>& data, std::shared_ptr<_CertType> input)
			{
#ifdef DECENT_THREAD_SAFETY_HIGH
				std::atomic_store(&data, input);
#else
				data = input;
#endif // DECENT_THREAD_SAFETY_HIGH
			}

		private:
			std::shared_ptr<const mbedTLScpp::X509Cert> m_cert;
		};
	}
}
