#pragma once

#include <memory>
#include <functional>

#include "MbedTlsObjects.h"

namespace Decent
{
	namespace Crypto
	{
		constexpr char const X509ExtPlatformTypeOid[] = "2.25.294010332531314719175946865483017979201";
		constexpr char const X509ExtSelfRaReportOid[] = "2.25.210204819921761154072721866869208165061";
		constexpr char const X509ExtLaIdentityOid[] = "2.25.128165920542469106824459777090692906263";

		const mbedtls_x509_crt_profile& GetX509Profile();

		typedef std::function<bool(const MbedTlsObj::ECKeyPublic&, const std::string&, const std::string&)> ServerRaReportVerfier;
		typedef std::function<bool(const MbedTlsObj::ECKeyPublic&, const std::string&, const std::string&)> AppIdVerfier;
	}

	class X509Req : public MbedTlsObj::X509Req
	{
	public:
		X509Req() = delete;
		X509Req(const std::string& pemStr);
		X509Req(mbedtls_x509_csr* ptr, const std::string& pemStr);
		X509Req(const MbedTlsObj::ECKeyPublic& keyPair, const std::string& commonName);
		virtual ~X509Req() {}

		virtual void Destroy() override;
		virtual operator bool() const override;

		const MbedTlsObj::ECKeyPublic& GetEcPublicKey() const;

	private:
		MbedTlsObj::ECKeyPublic m_ecPubKey;
	};

	class ServerX509 : public MbedTlsObj::X509Cert
	{
	public:
		ServerX509() = delete;
		ServerX509(const std::string & pemStr);
		ServerX509(mbedtls_x509_crt* cert);
		ServerX509(const MbedTlsObj::ECKeyPair& prvKey, const std::string& enclaveHash, const std::string& platformType, const std::string& selfRaReport);
		virtual ~ServerX509() {}

		virtual void Destroy() override;
		virtual operator bool() const override;

		const std::string& GetPlatformType() const;
		const std::string& GetSelfRaReport() const;

		const MbedTlsObj::ECKeyPublic& GetEcPublicKey() const;

	private:
		void ParseExtensions();

		std::string m_platformType;
		std::string m_selfRaReport;
		MbedTlsObj::ECKeyPublic m_ecPubKey;
	};

	class AppX509 : public MbedTlsObj::X509Cert
	{
	public:
		AppX509() = delete;
		AppX509(const std::string & pemStr);
		AppX509(mbedtls_x509_crt* cert);
		AppX509(const MbedTlsObj::ECKeyPublic& pubKey,
			const ServerX509& caCert, const MbedTlsObj::ECKeyPair& serverPrvKey, 
			const std::string& enclaveHash, const std::string& platformType, const std::string& appId);
		virtual ~AppX509() {}

		virtual void Destroy() override;
		virtual operator bool() const override;

		const std::string& GetPlatformType() const;
		const std::string& GetAppId() const;

		const MbedTlsObj::ECKeyPublic& GetEcPublicKey() const;

	private:
		void ParseExtensions();

		std::string m_platformType;
		std::string m_appId;
		MbedTlsObj::ECKeyPublic m_ecPubKey;
	};

	class TlsConfig : public MbedTlsObj::TlsConfig
	{
	public:
		TlsConfig(Decent::Crypto::AppIdVerfier appIdVerifier, bool isServer);

		TlsConfig(Decent::Crypto::AppIdVerfier appIdVerifier, Decent::Crypto::ServerRaReportVerfier serverReportVerifier, bool isServer);

		TlsConfig(TlsConfig&& other);
		virtual ~TlsConfig() {}

		virtual TlsConfig& operator=(TlsConfig&& other);

		virtual void Destroy() override;

	private:
		static TlsConfig ConstructTlsConfig(bool isServer);
		static int CertVerifyCallBack(void* inst, mbedtls_x509_crt* cert, int depth, uint32_t* flag);
		int CertVerifyCallBack(mbedtls_x509_crt* cert, int depth, uint32_t* flag);
		TlsConfig(mbedtls_ssl_config* ptr);

		std::shared_ptr<const MbedTlsObj::ECKeyPair> m_prvKey;
		std::shared_ptr<const AppX509> m_appCert;
		std::shared_ptr<const ServerX509> m_decentCert;
		Decent::Crypto::ServerRaReportVerfier m_decentCertVerifier;
		Decent::Crypto::AppIdVerfier m_appCertVerifier;
		void* m_rng;
	};
}
