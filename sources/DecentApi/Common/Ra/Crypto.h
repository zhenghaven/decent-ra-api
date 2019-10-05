#pragma once

#include <memory>

#include "../MbedTls/EcKey.h"
#include "../MbedTls/MbedTlsObjects.h"

namespace Decent
{
	namespace MbedTlsObj
	{
		class EcKeyPairBase;
		class EcPublicKeyBase;
	}

	namespace Ra
	{
		constexpr char const gsk_x509PlatformTypeOid[] = "2.25.294010332531314719175946865483017979201";
		constexpr char const gsk_x509SelfRaReportOid[] = "2.25.210204819921761154072721866869208165061";
		constexpr char const gsk_x509LaIdOid[]         = "2.25.128165920542469106824459777090692906263";
		constexpr char const gsk_x509WhiteListOid[]    = "2.25.219117063696833207876173044031738000021";

		const mbedtls_x509_crt_profile& GetX509Profile();

		std::string GetHashFromAppId(const std::string& platformType, const std::string& appIdStr);

		class ServerX509 : public MbedTlsObj::X509Cert
		{
		public:
			ServerX509() = delete;
			ServerX509(const std::string& pemStr);
			ServerX509(mbedtls_x509_crt& cert);
			ServerX509(const MbedTlsObj::EcKeyPairBase& prvKey, const std::string& enclaveHash, const std::string& platformType, const std::string& selfRaReport);

			ServerX509(ServerX509&& other) :
				m_platformType(std::move(other.m_platformType)),
				m_selfRaReport(std::move(other.m_selfRaReport)),
				m_ecPubKey(std::move(other.m_ecPubKey))
			{}

			ServerX509(const ServerX509& other) = delete;
			virtual ~ServerX509() {}

			virtual ServerX509& operator=(const ServerX509& other) = delete;

			virtual ServerX509& operator=(ServerX509&& other)
			{
				MbedTlsObj::X509Cert::operator=(std::forward<MbedTlsObj::X509Cert>(other));
				if (this != &other)
				{
					m_platformType.swap(other.m_platformType);
					m_selfRaReport.swap(other.m_selfRaReport);
					m_ecPubKey = std::move(other.m_ecPubKey);
				}
				return *this;
			}

			virtual operator bool() const noexcept override;

			const std::string& GetPlatformType() const { return m_platformType; }
			const std::string& GetSelfRaReport() const { return m_selfRaReport; }

			const MbedTlsObj::EcPublicKeyBase& GetEcPublicKey() const { return m_ecPubKey; }

		private:
			void ParseExtensions();

			std::string m_platformType;
			std::string m_selfRaReport;
			MbedTlsObj::EcPublicKeyBase m_ecPubKey;
		};

		class AppX509 : public MbedTlsObj::X509Cert
		{
		public:
			AppX509() = delete;
			AppX509(const std::string & pemStr);
			AppX509(mbedtls_x509_crt& cert);
			AppX509(const MbedTlsObj::EcPublicKeyBase& pubKey,
				const ServerX509& caCert, const MbedTlsObj::EcKeyPairBase& serverPrvKey,
				const std::string& enclaveHash, const std::string& platformType, const std::string& appId, const std::string& whiteList);

			AppX509(AppX509&& other) :
				m_platformType(std::move(other.m_platformType)),
				m_appId(std::move(other.m_appId)),
				m_whiteList(std::move(other.m_whiteList)),
				m_ecPubKey(std::move(other.m_ecPubKey))
			{}

			AppX509(const AppX509& other) = delete;
			
			virtual ~AppX509() {}

			virtual AppX509& operator=(const AppX509& other) = delete;

			virtual AppX509& operator=(AppX509&& other)
			{
				MbedTlsObj::X509Cert::operator=(std::forward<MbedTlsObj::X509Cert>(other));
				if (this != &other)
				{
					m_platformType.swap(other.m_platformType);
					m_appId.swap(other.m_appId);
					m_ecPubKey = std::move(other.m_ecPubKey);
				}
				return *this;
			}

			virtual operator bool() const noexcept override;

			const std::string& GetPlatformType() const { return m_platformType; }
			const std::string& GetAppId() const { return m_appId; }
			const std::string& GetWhiteList() const { return m_whiteList; }

			const MbedTlsObj::EcPublicKeyBase& GetEcPublicKey() const { return m_ecPubKey; }

		protected:
			AppX509(const MbedTlsObj::EcPublicKeyBase& pubKey,
				const MbedTlsObj::X509Cert& caCert, const MbedTlsObj::EcKeyPairBase& serverPrvKey,
				const std::string& commonName, const std::string& platformType, const std::string& appId, const std::string& whiteList);

		private:
			void ParseExtensions();

			std::string m_platformType;
			std::string m_appId;
			std::string m_whiteList;
			MbedTlsObj::EcPublicKeyBase m_ecPubKey;
		};
	}
}
