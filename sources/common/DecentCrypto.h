#pragma once

#include "MbedTlsObjects.h"

namespace DecentCrypto
{
	constexpr char const X509ExtPlatformTypeOid[] = "2.25.294010332531314719175946865483017979201";
	constexpr char const X509ExtSelfRaReportOid[] = "2.25.210204819921761154072721866869208165061";
	constexpr char const X509ExtLaIdentityOid[]   = "2.25.128165920542469106824459777090692906263";

	const mbedtls_x509_crt_profile& GetX509Profile();
}

class MbedTlsDecentX509Req : public MbedTlsObj::X509Req
{
public:
	MbedTlsDecentX509Req() = delete;
	MbedTlsDecentX509Req(const std::string& pemStr);
	MbedTlsDecentX509Req(mbedtls_x509_csr* ptr, const std::string& pemStr);
	MbedTlsDecentX509Req(const MbedTlsObj::ECKeyPublic& keyPair, const std::string& commonName);
	virtual ~MbedTlsDecentX509Req() {}

	virtual void Destory() override;
	virtual operator bool() const override;

	const MbedTlsObj::ECKeyPublic& GetEcPublicKey() const;

private:
	MbedTlsObj::ECKeyPublic m_ecPubKey;
};

class MbedTlsDecentServerX509 : public MbedTlsObj::X509Cert
{
public:
	MbedTlsDecentServerX509() = delete;
	MbedTlsDecentServerX509(const std::string & pemStr);
	MbedTlsDecentServerX509(const MbedTlsObj::ECKeyPair& prvKey, const std::string& enclaveHash, const std::string& platformType, const std::string& selfRaReport);
	virtual ~MbedTlsDecentServerX509() {}

	virtual void Destory() override;
	virtual operator bool() const override;

	const std::string& GetPlatformType() const;
	const std::string& GetSelfRaReport() const;

	const MbedTlsObj::ECKeyPublic& GetEcPublicKey() const;

private:
	std::string m_platformType;
	std::string m_selfRaReport;
	MbedTlsObj::ECKeyPublic m_ecPubKey;
};

class MbedTlsDecentAppX509 : public MbedTlsObj::X509Cert
{
public:
	MbedTlsDecentAppX509() = delete;
	MbedTlsDecentAppX509(const std::string & pemStr);
	MbedTlsDecentAppX509(const MbedTlsObj::ECKeyPublic& pubKey, 
		const MbedTlsDecentServerX509& caCert, const MbedTlsObj::ECKeyPair& serverPrvKey, 
		const std::string& enclaveHash, const std::string& platformType, const std::string& appId);
	virtual ~MbedTlsDecentAppX509() {}

	virtual void Destory() override;
	virtual operator bool() const override;

	const std::string& GetPlatformType() const;
	const std::string& GetAppId() const;

	const MbedTlsObj::ECKeyPublic& GetEcPublicKey() const;

private:
	std::string m_platformType;
	std::string m_appId;
	MbedTlsObj::ECKeyPublic m_ecPubKey;
};
