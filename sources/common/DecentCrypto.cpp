#include "DecentCrypto.h"

#include <climits>

#include <mbedtls/x509_csr.h>
#include <mbedtls/x509_crt.h>

const mbedtls_x509_crt_profile & DecentCrypto::GetX509Profile()
{
	static const mbedtls_x509_crt_profile inst = {
		mbedtls_md_type_t::MBEDTLS_MD_SHA256,
		mbedtls_pk_type_t::MBEDTLS_PK_ECKEY,
		mbedtls_ecp_group_id::MBEDTLS_ECP_DP_SECP256R1,
		UINT32_MAX
	};
	
	return inst;
}

MbedTlsDecentX509Req::MbedTlsDecentX509Req(const std::string & pemStr) :
	X509Req(pemStr),
	m_ecPubKey(m_ptr && mbedtls_pk_get_type(&m_ptr->pk) == mbedtls_pk_type_t::MBEDTLS_PK_ECKEY
		? &m_ptr->pk : nullptr, false)
{
}

MbedTlsDecentX509Req::MbedTlsDecentX509Req(mbedtls_x509_csr * ptr, const std::string & pemStr) :
	X509Req(ptr, pemStr),
	m_ecPubKey(m_ptr && mbedtls_pk_get_type(&m_ptr->pk) == mbedtls_pk_type_t::MBEDTLS_PK_ECKEY
		? &m_ptr->pk : nullptr, false)
{
}

MbedTlsDecentX509Req::MbedTlsDecentX509Req(const MbedTlsObj::ECKeyPublic & keyPair, const std::string & commonName) :
	X509Req(keyPair, commonName),
	m_ecPubKey(m_ptr && mbedtls_pk_get_type(&m_ptr->pk) == mbedtls_pk_type_t::MBEDTLS_PK_ECKEY
		? &m_ptr->pk : nullptr, false)
{
}

void MbedTlsDecentX509Req::Destory()
{
	X509Req::Destory();
	m_ecPubKey.Destory();
}

MbedTlsDecentX509Req::operator bool() const
{
	return X509Req::operator bool() && m_ecPubKey;
}

const MbedTlsObj::ECKeyPublic & MbedTlsDecentX509Req::GetEcPublicKey() const
{
	return m_ecPubKey;
}

MbedTlsDecentServerX509::MbedTlsDecentServerX509(const std::string & pemStr) :
	X509Cert(pemStr),
	m_ecPubKey(m_ptr && mbedtls_pk_get_type(&m_ptr->pk) == mbedtls_pk_type_t::MBEDTLS_PK_ECKEY
		? &m_ptr->pk : nullptr, false)
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
	m_selfRaReport(selfRaReport),
	m_ecPubKey(m_ptr && mbedtls_pk_get_type(&m_ptr->pk) == mbedtls_pk_type_t::MBEDTLS_PK_ECKEY
		? &m_ptr->pk : nullptr, false)
{
}

void MbedTlsDecentServerX509::Destory()
{
	X509Cert::Destory();
	m_ecPubKey.Destory();
	m_platformType.clear();
	m_selfRaReport.clear();
}

MbedTlsDecentServerX509::operator bool() const
{
	return X509Cert::operator bool() && m_ecPubKey;
}

const std::string & MbedTlsDecentServerX509::GetPlatformType() const
{
	return m_platformType;
}

const std::string & MbedTlsDecentServerX509::GetSelfRaReport() const
{
	
	return m_selfRaReport;
}

const MbedTlsObj::ECKeyPublic & MbedTlsDecentServerX509::GetEcPublicKey() const
{
	return m_ecPubKey;
}

MbedTlsDecentAppX509::MbedTlsDecentAppX509(const std::string & pemStr) :
	X509Cert(pemStr),
	m_ecPubKey(m_ptr && mbedtls_pk_get_type(&m_ptr->pk) == mbedtls_pk_type_t::MBEDTLS_PK_ECKEY
		? &m_ptr->pk : nullptr, false)
{
	std::map<std::string, std::pair<bool, std::string> > extMap =
	{
		std::pair<std::string, std::pair<bool, std::string> >(DecentCrypto::X509ExtPlatformTypeOid, std::pair<bool, std::string>(false, std::string())),
		std::pair<std::string, std::pair<bool, std::string> >(DecentCrypto::X509ExtLaIdentityOid, std::pair<bool, std::string>(false, std::string())),
	};

	if (GetExtensions(extMap))
	{
		m_platformType.swap(extMap[DecentCrypto::X509ExtPlatformTypeOid].second);
		m_appId.swap(extMap[DecentCrypto::X509ExtLaIdentityOid].second);
	}
}

MbedTlsDecentAppX509::MbedTlsDecentAppX509(const MbedTlsObj::ECKeyPublic & pubKey, 
	const MbedTlsDecentServerX509 & caCert, const MbedTlsObj::ECKeyPair & serverPrvKey, 
	const std::string & enclaveHash, const std::string & platformType, const std::string & appId) :
	X509Cert(caCert, serverPrvKey, pubKey, MbedTlsObj::BigNumber::GenRandomNumber(GENERAL_256BIT_32BYTE_SIZE), LONG_MAX, true, -1,
		MBEDTLS_X509_KU_NON_REPUDIATION | MBEDTLS_X509_KU_DIGITAL_SIGNATURE | MBEDTLS_X509_KU_KEY_AGREEMENT | MBEDTLS_X509_KU_KEY_CERT_SIGN | MBEDTLS_X509_KU_CRL_SIGN,
		MBEDTLS_X509_NS_CERT_TYPE_SSL_CA | MBEDTLS_X509_NS_CERT_TYPE_SSL_CLIENT | MBEDTLS_X509_NS_CERT_TYPE_SSL_SERVER,
		("CN=" + enclaveHash).c_str(),
		std::map<std::string, std::pair<bool, std::string> >{
		std::pair<std::string, std::pair<bool, std::string> >(DecentCrypto::X509ExtPlatformTypeOid, std::pair<bool, std::string>(false, platformType)),
		std::pair<std::string, std::pair<bool, std::string> >(DecentCrypto::X509ExtLaIdentityOid, std::pair<bool, std::string>(false, appId)),
	}
	),
	m_platformType(platformType),
	m_appId(appId),
	m_ecPubKey(m_ptr && mbedtls_pk_get_type(&m_ptr->pk) == mbedtls_pk_type_t::MBEDTLS_PK_ECKEY
		? &m_ptr->pk : nullptr, false)
{
}

void MbedTlsDecentAppX509::Destory()
{
	X509Cert::Destory();
	m_ecPubKey.Destory();
	m_platformType.clear();
	m_appId.clear();
}

MbedTlsDecentAppX509::operator bool() const
{
	return X509Cert::operator bool() && m_ecPubKey;
}

const std::string & MbedTlsDecentAppX509::GetPlatformType() const
{
	return m_platformType;
}

const std::string & MbedTlsDecentAppX509::GetAppId() const
{
	return m_appId;
}

const MbedTlsObj::ECKeyPublic & MbedTlsDecentAppX509::GetEcPublicKey() const
{
	return m_ecPubKey;
}
