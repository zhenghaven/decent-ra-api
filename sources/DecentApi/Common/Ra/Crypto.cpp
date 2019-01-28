#include "Crypto.h"

#include <climits>

#include <mbedtls/x509_csr.h>
#include <mbedtls/x509_crt.h>

#include <sgx_dh.h>

#include "../Common.h"
#include "../Tools/DataCoding.h"
#include "../MbedTls/MbedTlsHelpers.h"

#include "RaReport.h"

using namespace Decent;
using namespace Decent::Ra;
using namespace Decent::Tools;

namespace
{
	static constexpr int MBEDTLS_SUCCESS_RET = 0;
}

const mbedtls_x509_crt_profile & Decent::Ra::GetX509Profile()
{
	static const mbedtls_x509_crt_profile inst = {
		mbedtls_md_type_t::MBEDTLS_MD_SHA256,
		mbedtls_pk_type_t::MBEDTLS_PK_ECKEY,
		mbedtls_ecp_group_id::MBEDTLS_ECP_DP_SECP256R1,
		UINT32_MAX
	};
	
	return inst;
}

std::string Decent::Ra::GetHashFromAppId(const std::string & platformType, const std::string & appIdStr)
{
	if (platformType == RaReport::sk_ValueReportTypeSgx)
	{
		sgx_dh_session_enclave_identity_t appId;
		DeserializeStruct(appId, appIdStr);

		return SerializeStruct(appId.mr_enclave);
	}
	return std::string();
}

X509Req::X509Req(const std::string & pemStr) :
	MbedTlsObj::X509Req(pemStr),
	m_ecPubKey(m_ptr && mbedtls_pk_get_type(&m_ptr->pk) == mbedtls_pk_type_t::MBEDTLS_PK_ECKEY
		? &m_ptr->pk : nullptr, false)
{
}

X509Req::X509Req(mbedtls_x509_csr * ptr, const std::string & pemStr) :
	MbedTlsObj::X509Req(ptr, pemStr),
	m_ecPubKey(m_ptr && mbedtls_pk_get_type(&m_ptr->pk) == mbedtls_pk_type_t::MBEDTLS_PK_ECKEY
		? &m_ptr->pk : nullptr, false)
{
}

X509Req::X509Req(const MbedTlsObj::ECKeyPublic & keyPair, const std::string & commonName) :
	MbedTlsObj::X509Req(keyPair, commonName),
	m_ecPubKey(m_ptr && mbedtls_pk_get_type(&m_ptr->pk) == mbedtls_pk_type_t::MBEDTLS_PK_ECKEY
		? &m_ptr->pk : nullptr, false)
{
}

void X509Req::Destroy()
{
	MbedTlsObj::X509Req::Destroy();
	m_ecPubKey.Destroy();
}

X509Req& X509Req::operator=(X509Req&& other)
{
	if (this != &other)
	{
		MbedTlsObj::X509Req::operator=(std::forward<MbedTlsObj::X509Req>(other));
		m_ecPubKey = std::move(other.m_ecPubKey);
	}
	return *this;
}

X509Req::operator bool() const
{
	return MbedTlsObj::X509Req::operator bool() && m_ecPubKey;
}

const MbedTlsObj::ECKeyPublic & X509Req::GetEcPublicKey() const
{
	return m_ecPubKey;
}

ServerX509::ServerX509(const std::string & pemStr) :
	MbedTlsObj::X509Cert(pemStr),
	m_ecPubKey(m_ptr && mbedtls_pk_get_type(&m_ptr->pk) == mbedtls_pk_type_t::MBEDTLS_PK_ECKEY
		? &m_ptr->pk : nullptr, false)
{
	ParseExtensions();
}

ServerX509::ServerX509(mbedtls_x509_crt * cert) :
	MbedTlsObj::X509Cert(cert),
	m_ecPubKey(m_ptr && mbedtls_pk_get_type(&m_ptr->pk) == mbedtls_pk_type_t::MBEDTLS_PK_ECKEY
		? &m_ptr->pk : nullptr, false)
{
	ParseExtensions();
}

ServerX509::ServerX509(const MbedTlsObj::ECKeyPair & prvKey, const std::string & enclaveHash, const std::string & platformType, const std::string & selfRaReport) :
	MbedTlsObj::X509Cert(prvKey, MbedTlsObj::BigNumber::GenRandomNumber(GENERAL_256BIT_32BYTE_SIZE), LONG_MAX, true, -1,
		MBEDTLS_X509_KU_NON_REPUDIATION | MBEDTLS_X509_KU_DIGITAL_SIGNATURE | MBEDTLS_X509_KU_KEY_AGREEMENT | MBEDTLS_X509_KU_KEY_CERT_SIGN | MBEDTLS_X509_KU_CRL_SIGN,
		MBEDTLS_X509_NS_CERT_TYPE_SSL_CA | MBEDTLS_X509_NS_CERT_TYPE_SSL_CLIENT | MBEDTLS_X509_NS_CERT_TYPE_SSL_SERVER,
		("CN=" + enclaveHash).c_str(),
		std::map<std::string, std::pair<bool, std::string> >{
		std::pair<std::string, std::pair<bool, std::string> >(Decent::Ra::gsk_x509PlatformTypeOid, std::pair<bool, std::string>(false, platformType)),
		std::pair<std::string, std::pair<bool, std::string> >(Decent::Ra::gsk_x509SelfRaReportOid, std::pair<bool, std::string>(false, selfRaReport)),
		}
	),
	m_platformType(platformType),
	m_selfRaReport(selfRaReport),
	m_ecPubKey(m_ptr && mbedtls_pk_get_type(&m_ptr->pk) == mbedtls_pk_type_t::MBEDTLS_PK_ECKEY
		? &m_ptr->pk : nullptr, false)
{
}

void ServerX509::ParseExtensions()
{
	std::map<std::string, std::pair<bool, std::string> > extMap =
	{
		std::pair<std::string, std::pair<bool, std::string> >(Decent::Ra::gsk_x509PlatformTypeOid, std::pair<bool, std::string>(false, std::string())),
		std::pair<std::string, std::pair<bool, std::string> >(Decent::Ra::gsk_x509SelfRaReportOid, std::pair<bool, std::string>(false, std::string())),
	};

	if (GetExtensions(extMap))
	{
		m_platformType.swap(extMap[Decent::Ra::gsk_x509PlatformTypeOid].second);
		m_selfRaReport.swap(extMap[Decent::Ra::gsk_x509SelfRaReportOid].second);
	}
}

void ServerX509::Destroy()
{
	MbedTlsObj::X509Cert::Destroy();
	m_ecPubKey.Destroy();
	m_platformType.clear();
	m_selfRaReport.clear();
}

ServerX509& ServerX509::operator=(ServerX509&& other)
{
	if (this != &other)
	{
		MbedTlsObj::X509Cert::operator=(std::forward<MbedTlsObj::X509Cert>(other));
		m_platformType = std::move(other.m_platformType);
		m_selfRaReport = std::move(other.m_selfRaReport);
		m_ecPubKey = std::move(other.m_ecPubKey);
	}
	return *this;
}

ServerX509::operator bool() const
{
	return MbedTlsObj::X509Cert::operator bool() && m_ecPubKey && m_platformType.size() > 0 && m_selfRaReport.size() > 0;
}

const std::string & ServerX509::GetPlatformType() const
{
	return m_platformType;
}

const std::string & ServerX509::GetSelfRaReport() const
{
	
	return m_selfRaReport;
}

const MbedTlsObj::ECKeyPublic & ServerX509::GetEcPublicKey() const
{
	return m_ecPubKey;
}

AppX509::AppX509(const std::string & pemStr) :
	MbedTlsObj::X509Cert(pemStr),
	m_ecPubKey(m_ptr && mbedtls_pk_get_type(&m_ptr->pk) == mbedtls_pk_type_t::MBEDTLS_PK_ECKEY
		? &m_ptr->pk : nullptr, false)
{
	ParseExtensions();
}

AppX509::AppX509(mbedtls_x509_crt * cert) :
	MbedTlsObj::X509Cert(cert),
	m_ecPubKey(m_ptr && mbedtls_pk_get_type(&m_ptr->pk) == mbedtls_pk_type_t::MBEDTLS_PK_ECKEY
		? &m_ptr->pk : nullptr, false)
{
	ParseExtensions();
}

AppX509::AppX509(const MbedTlsObj::ECKeyPublic & pubKey, 
	const ServerX509 & caCert, const MbedTlsObj::ECKeyPair & serverPrvKey, 
	const std::string & enclaveHash, const std::string & platformType, const std::string & appId, const std::string& whiteList) :
	AppX509(pubKey, static_cast<const MbedTlsObj::X509Cert &>(caCert), serverPrvKey, enclaveHash, platformType, appId, whiteList)
{
}

AppX509::AppX509(const MbedTlsObj::ECKeyPublic & pubKey, 
	const MbedTlsObj::X509Cert & caCert, const MbedTlsObj::ECKeyPair & serverPrvKey, 
	const std::string & commonName, const std::string & platformType, const std::string & appId, const std::string & whiteList) :
	MbedTlsObj::X509Cert(caCert, serverPrvKey, pubKey, MbedTlsObj::BigNumber::GenRandomNumber(GENERAL_256BIT_32BYTE_SIZE), LONG_MAX, true, -1,
		MBEDTLS_X509_KU_NON_REPUDIATION | MBEDTLS_X509_KU_DIGITAL_SIGNATURE | MBEDTLS_X509_KU_KEY_AGREEMENT | MBEDTLS_X509_KU_KEY_CERT_SIGN | MBEDTLS_X509_KU_CRL_SIGN,
		MBEDTLS_X509_NS_CERT_TYPE_SSL_CA | MBEDTLS_X509_NS_CERT_TYPE_SSL_CLIENT | MBEDTLS_X509_NS_CERT_TYPE_SSL_SERVER,
		("CN=" + commonName).c_str(),
		std::map<std::string, std::pair<bool, std::string> >{
			std::pair<std::string, std::pair<bool, std::string> >(Decent::Ra::gsk_x509PlatformTypeOid, std::pair<bool, std::string>(false, platformType)),
			std::pair<std::string, std::pair<bool, std::string> >(Decent::Ra::gsk_x509LaIdOid, std::pair<bool, std::string>(false, appId)),
			std::pair<std::string, std::pair<bool, std::string> >(Decent::Ra::gsk_x509WhiteListOid, std::pair<bool, std::string>(false, whiteList)),
		}
	),
	m_platformType(platformType),
	m_appId(appId),
	m_whiteList(whiteList),
	m_ecPubKey(m_ptr && mbedtls_pk_get_type(&m_ptr->pk) == mbedtls_pk_type_t::MBEDTLS_PK_ECKEY
		? &m_ptr->pk : nullptr, false)
{
}

void AppX509::Destroy()
{
	MbedTlsObj::X509Cert::Destroy();
	m_ecPubKey.Destroy();
	m_platformType.clear();
	m_appId.clear();
}

AppX509& AppX509::operator=(AppX509&& other)
{
	if (this != &other)
	{
		MbedTlsObj::X509Cert::operator=(std::forward<MbedTlsObj::X509Cert>(other));
		m_platformType = std::move(other.m_platformType);
		m_appId = std::move(other.m_appId);
		m_ecPubKey = std::move(other.m_ecPubKey);
	}
	return *this;
}

AppX509::operator bool() const
{
	return MbedTlsObj::X509Cert::operator bool() && m_ecPubKey && m_platformType.size() > 0 && m_appId.size() > 0 && m_whiteList.size() > 0;
}

const std::string & AppX509::GetPlatformType() const
{
	return m_platformType;
}

const std::string & AppX509::GetAppId() const
{
	return m_appId;
}

const std::string & AppX509::GetWhiteList() const
{
	return m_whiteList;
}

const MbedTlsObj::ECKeyPublic & AppX509::GetEcPublicKey() const
{
	return m_ecPubKey;
}

void AppX509::ParseExtensions()
{
	std::map<std::string, std::pair<bool, std::string> > extMap =
	{
		std::pair<std::string, std::pair<bool, std::string> >(Decent::Ra::gsk_x509PlatformTypeOid, std::pair<bool, std::string>(false, std::string())),
		std::pair<std::string, std::pair<bool, std::string> >(Decent::Ra::gsk_x509LaIdOid, std::pair<bool, std::string>(false, std::string())),
		std::pair<std::string, std::pair<bool, std::string> >(Decent::Ra::gsk_x509WhiteListOid, std::pair<bool, std::string>(false, std::string())),
	};

	if (GetExtensions(extMap))
	{
		m_platformType.swap(extMap[Decent::Ra::gsk_x509PlatformTypeOid].second);
		m_appId.swap(extMap[Decent::Ra::gsk_x509LaIdOid].second);
		m_whiteList.swap(extMap[Decent::Ra::gsk_x509WhiteListOid].second);
	}
}
