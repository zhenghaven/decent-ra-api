#include "DecentCrypto.h"

#include <mbedtls/x509_crt.h>

MbedTlsDecentServerX509::MbedTlsDecentServerX509(const std::string & pemStr) :
	X509Cert(pemStr)
{
	std::map<std::string, std::pair<bool, std::string> > extMap = 
	{
		std::pair<std::string, std::pair<bool, std::string> >(DecentCrypto::X509ExtPlatformTypeOid, std::pair<bool, std::string>(false, std::string())),
		std::pair<std::string, std::pair<bool, std::string> >(DecentCrypto::X509ExtSelfRaReportOid, std::pair<bool, std::string>(false, std::string())),
	};

	if (GetExtensions(extMap))
	{
		m_platformType.swap(extMap[DecentCrypto::X509ExtPlatformTypeOid].second);
		m_selfRaReport.swap(extMap[DecentCrypto::X509ExtSelfRaReportOid].second);
	}
}

MbedTlsDecentServerX509::MbedTlsDecentServerX509(const MbedTlsObj::ECKeyPair & prvKey, const std::string & enclaveHash, const std::string & platformType, const std::string & selfRaReport) :
	X509Cert(prvKey, MbedTlsObj::BigNumber::GenRandomNumber(GENERAL_256BIT_32BYTE_SIZE), LONG_MAX, true, -1,
		MBEDTLS_X509_KU_NON_REPUDIATION | MBEDTLS_X509_KU_DIGITAL_SIGNATURE | MBEDTLS_X509_KU_KEY_AGREEMENT | MBEDTLS_X509_KU_KEY_CERT_SIGN | MBEDTLS_X509_KU_CRL_SIGN,
		MBEDTLS_X509_NS_CERT_TYPE_SSL_CA | MBEDTLS_X509_NS_CERT_TYPE_SSL_CLIENT | MBEDTLS_X509_NS_CERT_TYPE_SSL_SERVER,
		("CN=" + enclaveHash).c_str(),
		std::map<std::string, std::pair<bool, std::string> >{
		std::pair<std::string, std::pair<bool, std::string> >(DecentCrypto::X509ExtPlatformTypeOid, std::pair<bool, std::string>(false, platformType)),
		std::pair<std::string, std::pair<bool, std::string> >(DecentCrypto::X509ExtSelfRaReportOid, std::pair<bool, std::string>(false, selfRaReport)),
		}
	),
	m_platformType(platformType),
	m_selfRaReport(selfRaReport)
{
}

