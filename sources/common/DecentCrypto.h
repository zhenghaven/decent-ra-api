#pragma once

#include "MbedTlsObjects.h"

namespace DecentCrypto
{
	constexpr char const X509ExtPlatformTypeOid[] = "2.25.294010332531314719175946865483017979201";
	constexpr char const X509ExtSelfRaReportOid[] = "2.25.210204819921761154072721866869208165061";
	constexpr char const X509ExtLaIdentityOid[]   = "2.25.128165920542469106824459777090692906263";
}

class MbedTlsDecentServerX509 : public MbedTlsObj::X509Cert
{
public:
	MbedTlsDecentServerX509() = delete;
	MbedTlsDecentServerX509(const std::string & pemStr);
	MbedTlsDecentServerX509(const MbedTlsObj::ECKeyPair& prvKey, const std::string& enclaveHash, const std::string& platformType, const std::string& selfRaReport);
	~MbedTlsDecentServerX509() {}

	const std::string& GetPlatformType() const;
	const std::string& GetSelfRaReport() const;

private:
	std::string m_platformType;
	std::string m_selfRaReport;
};

class MbedTlsDecentAppX509 : public MbedTlsObj::X509Cert
{
public:
	MbedTlsDecentAppX509() = delete;
	MbedTlsDecentAppX509(const std::string & pemStr);
	MbedTlsDecentAppX509(const MbedTlsObj::ECKeyPublic& pubKey, 
		const MbedTlsDecentServerX509& caCert, const MbedTlsObj::ECKeyPair& serverPrvKey, 
		const std::string& enclaveHash, const std::string& platformType, const std::string& appId);
	~MbedTlsDecentAppX509() {}

	const std::string& GetPlatformType() const;
	const std::string& GetAppId() const;

private:
	std::string m_platformType;
	std::string m_appId;
};
