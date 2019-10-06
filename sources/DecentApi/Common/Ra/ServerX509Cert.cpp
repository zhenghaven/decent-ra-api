#include "ServerX509Cert.h"

#include <mbedtls/x509_crt.h>

#include "../Common.h"
#include "../GeneralKeyTypes.h"

#include "../MbedTls/Drbg.h"
#include "../MbedTls/EcKey.h"
#include "../MbedTls/BigNumber.h"

#include "Internal/Cert.h"

using namespace Decent::Ra;
using namespace Decent::Tools;
using namespace Decent::MbedTlsObj;

const mbedtls_x509_crt_profile & Decent::Ra::GetX509Profile()
{
	return mbedtls_x509_crt_profile_suiteb;
}

ServerX509CertWriter::ServerX509CertWriter(EcKeyPairBase & prvKey, const std::string & enclaveHash, const std::string & platformType, const std::string & selfRaReport) :
	X509CertWriter(HashType::SHA256, prvKey, ("CN=" + enclaveHash))
{
	SetBasicConstraints(true, -1);
	SetKeyUsage(MBEDTLS_X509_KU_NON_REPUDIATION | MBEDTLS_X509_KU_DIGITAL_SIGNATURE | MBEDTLS_X509_KU_KEY_AGREEMENT | MBEDTLS_X509_KU_KEY_CERT_SIGN | MBEDTLS_X509_KU_CRL_SIGN);
	SetNsType(MBEDTLS_X509_NS_CERT_TYPE_SSL_CA | MBEDTLS_X509_NS_CERT_TYPE_SSL_CLIENT | MBEDTLS_X509_NS_CERT_TYPE_SSL_SERVER);

	SetSerialNum(BigNumber::Rand<Drbg>(GENERAL_256BIT_32BYTE_SIZE));

	SetV3Extensions(
		std::map<std::string, std::pair<bool, std::string> >
	{
		std::make_pair(detail::gsk_x509PlatformTypeOid, std::make_pair(false, platformType)),
		std::make_pair(detail::gsk_x509SelfRaReportOid, std::make_pair(false, selfRaReport)),
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

ServerX509CertWriter::~ServerX509CertWriter()
{
}

ServerX509Cert::ServerX509Cert(const ServerX509Cert & rhs) :
	X509Cert(rhs),
	m_platformType(rhs.m_platformType),
	m_selfRaReport(rhs.m_selfRaReport)
{
}

ServerX509Cert::ServerX509Cert(ServerX509Cert && rhs) :
	X509Cert(std::forward<X509Cert>(rhs)),
	m_platformType(std::move(rhs.m_platformType)),
	m_selfRaReport(std::move(rhs.m_selfRaReport))
{}

ServerX509Cert::ServerX509Cert(const std::vector<uint8_t>& der) :
	X509Cert(der),
	m_platformType(),
	m_selfRaReport()
{
	ParseExtensions();
}

ServerX509Cert::ServerX509Cert(const std::string & pem) :
	X509Cert(pem),
	m_platformType(),
	m_selfRaReport()
{
	ParseExtensions();
}

ServerX509Cert::ServerX509Cert(mbedtls_x509_crt & ref) :
	X509Cert(ref),
	m_platformType(),
	m_selfRaReport()
{
	ParseExtensions();
}

ServerX509Cert::~ServerX509Cert()
{
}

ServerX509Cert & ServerX509Cert::operator=(ServerX509Cert && rhs)
{
	X509Cert::operator=(std::forward<X509Cert>(rhs));
	if (this != &rhs)
	{
		m_platformType = std::move(rhs.m_platformType);
		m_selfRaReport = std::move(rhs.m_selfRaReport);
	}
	return *this;
}

const std::string & ServerX509Cert::GetPlatformType() const
{
	return m_platformType;
}

const std::string & Decent::Ra::ServerX509Cert::GetSelfRaReport() const
{
	return m_selfRaReport;
}

void ServerX509Cert::ParseExtensions()
{
	auto extMap = GetCurrV3Extensions();

	auto it = extMap.find(detail::gsk_x509PlatformTypeOid);
	if (it == extMap.end())
	{
		throw RuntimeException("Invalid Server X509 certificate. Platform Type field is missing.");
	}

	m_platformType = std::move(it->second.second);

	it = extMap.find(detail::gsk_x509SelfRaReportOid);
	if (it == extMap.end())
	{
		throw RuntimeException("Invalid Server X509 certificate. Self RA Report field is missing.");
	}
	m_selfRaReport = std::move(it->second.second);
}
