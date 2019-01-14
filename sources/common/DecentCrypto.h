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
		X509Req(const X509Req& other) = delete;
		virtual ~X509Req() {}

		virtual void Destroy() override;
		virtual X509Req& operator=(const X509Req& other) = delete;
		virtual X509Req& operator=(X509Req&& other);
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
		ServerX509(const ServerX509& other) = delete;
		virtual ~ServerX509() {}

		virtual void Destroy() override;
		virtual ServerX509& operator=(const ServerX509& other) = delete;
		virtual ServerX509& operator=(ServerX509&& other);
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
		AppX509(const AppX509& other) = delete;
		virtual ~AppX509() {}

		virtual void Destroy() override;
		virtual AppX509& operator=(const AppX509& other) = delete;
		virtual AppX509& operator=(AppX509&& other);
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

		TlsConfig(TlsConfig&& other);
		TlsConfig(const TlsConfig& other) = delete;
		virtual ~TlsConfig() {}

		virtual TlsConfig& operator=(const TlsConfig& other) = delete;
		virtual TlsConfig& operator=(TlsConfig&& other);

		virtual void Destroy() override;

	private:
		static TlsConfig ConstructTlsConfig(bool isServer);
		static int CertVerifyCallBack(void* inst, mbedtls_x509_crt* cert, int depth, uint32_t* flag);
		int CertVerifyCallBack(mbedtls_x509_crt* cert, int depth, uint32_t* flag);
		TlsConfig(mbedtls_ssl_config* ptr);

		std::shared_ptr<const MbedTlsObj::ECKeyPair> m_prvKey;
		std::shared_ptr<const MbedTlsObj::X509Cert> m_cert;
		std::shared_ptr<const ServerX509> m_decentCert;
		Decent::Crypto::AppIdVerfier m_appCertVerifier;
	};
}
