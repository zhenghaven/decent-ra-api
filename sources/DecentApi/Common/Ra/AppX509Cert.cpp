#include "AppX509Cert.h"

#include <mbedtls/x509_crt.h>

#include "../Common.h"
#include "../GeneralKeyTypes.h"

#include "../MbedTls/Drbg.h"
#include "../MbedTls/EcKey.h"
#include "../MbedTls/BigNumber.h"

#include "ServerX509Cert.h"
#include "Internal/Cert.h"

using namespace Decent::Ra;
using namespace Decent::Tools;
using namespace Decent::MbedTlsObj;

AppX509CertWriter::AppX509CertWriter(EcPublicKeyBase & pubKey, const ServerX509Cert & svrCert, EcKeyPairBase & svrPrvKey,
	const std::string & enclaveHash, const std::string & platformType, const std::string & appId, const std::string & whiteList) :
	AppX509CertWriter(pubKey, static_cast<const X509Cert&>(svrCert), svrPrvKey, enclaveHash, platformType, appId, whiteList)
{
}

AppX509CertWriter::~AppX509CertWriter()
{
}

AppX509CertWriter::AppX509CertWriter(EcPublicKeyBase & pubKey, const X509Cert & svrCert, EcKeyPairBase & svrPrvKey,
	const std::string & enclaveHash, const std::string & platformType, const std::string & appId, const std::string & whiteList) :
	X509CertWriter(HashType::SHA256, svrCert, svrPrvKey, pubKey, ("CN=" + enclaveHash))
{
	SetBasicConstraints(true, -1);
	SetKeyUsage(MBEDTLS_X509_KU_NON_REPUDIATION | MBEDTLS_X509_KU_DIGITAL_SIGNATURE | MBEDTLS_X509_KU_KEY_AGREEMENT | MBEDTLS_X509_KU_KEY_CERT_SIGN | MBEDTLS_X509_KU_CRL_SIGN);
	SetNsType(MBEDTLS_X509_NS_CERT_TYPE_SSL_CA | MBEDTLS_X509_NS_CERT_TYPE_SSL_CLIENT | MBEDTLS_X509_NS_CERT_TYPE_SSL_SERVER);

	SetSerialNum(BigNumber::Rand<Drbg>(GENERAL_256BIT_32BYTE_SIZE));

	SetV3Extensions(
		std::map<std::string, std::pair<bool, std::string> >
	{
		std::make_pair(detail::gsk_x509PlatformTypeOid, std::make_pair(false, platformType)),
			std::make_pair(detail::gsk_x509LaIdOid, std::make_pair(false, appId)),
			std::make_pair(detail::gsk_x509WhiteListOid, std::make_pair(false, whiteList)),
	}
	);

	time_t timerBegin;
	GetSystemTime(timerBegin);
	time_t timerEnd = timerBegin + detail::gsk_x509ValidTime;

	std::tm timerBeginSt;
	std::tm timerEndSt;
	GetSystemUtcTime(timerBegin, timerBeginSt);
	GetSystemUtcTime(timerEnd, timerEndSt);

	SetValidationTime(detail::X509FormatTime(timerBeginSt), detail::X509FormatTime(timerEndSt));
}

AppX509Cert::AppX509Cert(AppX509Cert && other) :
	m_platformType(std::move(other.m_platformType)),
	m_appId(std::move(other.m_appId)),
	m_whiteList(std::move(other.m_whiteList))
{}

AppX509Cert::AppX509Cert(const std::vector<uint8_t>& der) :
	X509Cert(der),
	m_platformType(),
	m_appId(),
	m_whiteList()
{
	ParseExtensions();
}

AppX509Cert::AppX509Cert(const std::string & pem) :
	X509Cert(pem),
	m_platformType(),
	m_appId(),
	m_whiteList()
{
	ParseExtensions();
}

AppX509Cert::AppX509Cert(mbedtls_x509_crt & cert) :
	X509Cert(cert),
	m_platformType(),
	m_appId(),
	m_whiteList()
{
	ParseExtensions();
}

AppX509Cert::~AppX509Cert()
{
}

AppX509Cert & AppX509Cert::operator=(AppX509Cert && rhs)
{
	X509Cert::operator=(std::forward<X509Cert>(rhs));
	if (this != &rhs)
	{
		m_platformType = std::move(rhs.m_platformType);
		m_appId = std::move(rhs.m_appId);
		m_whiteList = std::move(rhs.m_whiteList);
	}
	return *this;
}

const std::string & AppX509Cert::GetPlatformType() const
{
	return m_platformType;
}

const std::string & AppX509Cert::GetAppId() const
{
	return m_appId;
}

const std::string & AppX509Cert::GetWhiteList() const
{
	return m_whiteList;
}

void AppX509Cert::ParseExtensions()
{
	auto extMap = GetCurrV3Extensions();

	auto it = extMap.find(detail::gsk_x509PlatformTypeOid);
	if (it == extMap.end())
	{
		throw RuntimeException("Invalid Server X509 certificate. Platform Type field is missing.");
	}

	m_platformType = std::move(it->second.second);

	it = extMap.find(detail::gsk_x509LaIdOid);
	if (it == extMap.end())
	{
		throw RuntimeException("Invalid Server X509 certificate. LA ID field is missing.");
	}
	m_appId = std::move(it->second.second);

	it = extMap.find(detail::gsk_x509WhiteListOid);
	if (it == extMap.end())
	{
		throw RuntimeException("Invalid Server X509 certificate. Whitelist field is missing.");
	}
	m_whiteList = std::move(it->second.second);
}
