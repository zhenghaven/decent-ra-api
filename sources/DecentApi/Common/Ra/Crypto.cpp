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
	m_ecPubKey(Get() && mbedtls_pk_get_type(&Get()->pk) == mbedtls_pk_type_t::MBEDTLS_PK_ECKEY
		? Get()->pk : MbedTlsObj::ECKeyPublic::Empty())
{
}

X509Req::X509Req(const MbedTlsObj::ECKeyPublic & keyPair, const std::string & commonName) :
	MbedTlsObj::X509Req(keyPair, commonName),
	m_ecPubKey(Get() && mbedtls_pk_get_type(&Get()->pk) == mbedtls_pk_type_t::MBEDTLS_PK_ECKEY
		? Get()->pk : MbedTlsObj::ECKeyPublic::Empty())
{
}

X509Req::operator bool() const noexcept
{
	return MbedTlsObj::X509Req::operator bool() && m_ecPubKey;
}

ServerX509::ServerX509(const std::string & pemStr) :
	MbedTlsObj::X509Cert(pemStr),
	m_ecPubKey(Get() && mbedtls_pk_get_type(&Get()->pk) == mbedtls_pk_type_t::MBEDTLS_PK_ECKEY
		? Get()->pk : MbedTlsObj::ECKeyPublic::Empty())
{
	ParseExtensions();
}

ServerX509::ServerX509(mbedtls_x509_crt & cert) :
	MbedTlsObj::X509Cert(cert),
	m_ecPubKey(Get() && mbedtls_pk_get_type(&Get()->pk) == mbedtls_pk_type_t::MBEDTLS_PK_ECKEY
		? Get()->pk : MbedTlsObj::ECKeyPublic::Empty())
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
	m_ecPubKey(Get() && mbedtls_pk_get_type(&Get()->pk) == mbedtls_pk_type_t::MBEDTLS_PK_ECKEY
		? Get()->pk : MbedTlsObj::ECKeyPublic::Empty())
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

ServerX509::operator bool() const noexcept
{
	return MbedTlsObj::X509Cert::operator bool() && m_ecPubKey && m_platformType.size() > 0 && m_selfRaReport.size() > 0;
}

AppX509::AppX509(const std::string & pemStr) :
	MbedTlsObj::X509Cert(pemStr),
	m_ecPubKey(Get() && mbedtls_pk_get_type(&Get()->pk) == mbedtls_pk_type_t::MBEDTLS_PK_ECKEY
		? Get()->pk : MbedTlsObj::ECKeyPublic::Empty())
{
	ParseExtensions();
}

AppX509::AppX509(mbedtls_x509_crt & cert) :
	MbedTlsObj::X509Cert(cert),
	m_ecPubKey(Get() && mbedtls_pk_get_type(&Get()->pk) == mbedtls_pk_type_t::MBEDTLS_PK_ECKEY
		? Get()->pk : MbedTlsObj::ECKeyPublic::Empty())
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
	m_ecPubKey(Get() && mbedtls_pk_get_type(&Get()->pk) == mbedtls_pk_type_t::MBEDTLS_PK_ECKEY
		? Get()->pk : MbedTlsObj::ECKeyPublic::Empty())
{
}

AppX509::operator bool() const noexcept
{
	return MbedTlsObj::X509Cert::operator bool() && m_ecPubKey && m_platformType.size() > 0 && m_appId.size() > 0 && m_whiteList.size() > 0;
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
