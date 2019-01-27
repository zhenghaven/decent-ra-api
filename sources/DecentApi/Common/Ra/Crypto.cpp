#include "Crypto.h"

#include <climits>

#include <mbedtls/x509_csr.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/ssl.h>

#include <sgx_dh.h>

#include "../Common.h"
#include "../Tools/DataCoding.h"
#include "../MbedTls/MbedTlsHelpers.h"

#include "States.h"
#include "KeyContainer.h"
#include "CertContainer.h"
#include "RaReport.h"
#include "WhiteList/DecentServer.h"
#include "WhiteList/HardCoded.h"
#include "WhiteList/Loaded.h"

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
	MbedTlsObj::X509Cert(caCert, serverPrvKey, pubKey, MbedTlsObj::BigNumber::GenRandomNumber(GENERAL_256BIT_32BYTE_SIZE), LONG_MAX, true, -1,
		MBEDTLS_X509_KU_NON_REPUDIATION | MBEDTLS_X509_KU_DIGITAL_SIGNATURE | MBEDTLS_X509_KU_KEY_AGREEMENT | MBEDTLS_X509_KU_KEY_CERT_SIGN | MBEDTLS_X509_KU_CRL_SIGN,
		MBEDTLS_X509_NS_CERT_TYPE_SSL_CA | MBEDTLS_X509_NS_CERT_TYPE_SSL_CLIENT | MBEDTLS_X509_NS_CERT_TYPE_SSL_SERVER,
		("CN=" + enclaveHash).c_str(),
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

int TlsConfig::CertVerifyCallBack(void * inst, mbedtls_x509_crt * cert, int depth, uint32_t * flag)
{
	if (!inst)
	{
		return MBEDTLS_ERR_X509_FATAL_ERROR;
	}
	return reinterpret_cast<TlsConfig*>(inst)->CertVerifyCallBack(cert, depth, flag);
}

int TlsConfig::CertVerifyCallBack(mbedtls_x509_crt * cert, int depth, uint32_t * flag) const
{
	switch (depth)
	{
	case 0: //App Cert
	{
		AppX509 appCert(cert);
		if (!appCert)
		{
			*flag = MBEDTLS_X509_BADCERT_NOT_TRUSTED;
			return MBEDTLS_SUCCESS_RET;
		}

		return AppCertVerifyCallBack(appCert, depth, *flag);
	}
	case 1: //Decent Cert
	{
		const ServerX509 serverCert(cert);
		if (!serverCert)
		{
			*flag = MBEDTLS_X509_BADCERT_NOT_TRUSTED;
			return MBEDTLS_SUCCESS_RET;
		}

		return ServerCertVerifyCallBack(serverCert, depth, *flag);
	}
	default:
		return MBEDTLS_ERR_X509_FATAL_ERROR;
	}
}

int TlsConfig::AppCertVerifyCallBack(const AppX509 & cert, int depth, uint32_t & flag) const
{
	using namespace Decent::Ra::WhiteList;

	if (flag != MBEDTLS_SUCCESS_RET)
	{//App cert is invalid!
		return MBEDTLS_SUCCESS_RET;
	}

	//Check Loaded Lists are match!!
	StaticTypeList peerLoadedList(Loaded::ParseWhiteListFromJson(cert.GetWhiteList()));
	if (peerLoadedList != States::Get().GetLoadedWhiteList())
	{
		flag = MBEDTLS_X509_BADCERT_NOT_TRUSTED;
		return MBEDTLS_SUCCESS_RET;
	}

	//Check peer's hash is in the white list.
	std::string peerHash = Decent::Ra::GetHashFromAppId(cert.GetPlatformType(), cert.GetAppId());

	if (!States::Get().GetLoadedWhiteList().CheckWhiteListWithHint(peerHash, m_expectedAppName) &&
		!States::Get().GetHardCodedWhiteList().CheckWhiteListWithHint(peerHash, m_expectedAppName))
	{
		flag = MBEDTLS_X509_BADCERT_NOT_TRUSTED;
		return MBEDTLS_SUCCESS_RET;
	}

	return MBEDTLS_SUCCESS_RET;
}

int TlsConfig::ServerCertVerifyCallBack(const ServerX509 & cert, int depth, uint32_t & flag) const
{
	const bool verifyRes = States::Get().GetServerWhiteList().AddTrustedNode(cert);
	flag = verifyRes ? MBEDTLS_SUCCESS_RET : MBEDTLS_X509_BADCERT_NOT_TRUSTED;
	return MBEDTLS_SUCCESS_RET;
}

TlsConfig::TlsConfig(const std::string& expectedAppName, bool isServer) :
	MbedTlsObj::TlsConfig(new mbedtls_ssl_config),
	m_prvKey(States::Get().GetKeyContainer().GetSignKeyPair()),
	m_cert(States::Get().GetCertContainer().GetCert()),
	m_expectedAppName(expectedAppName)
{
	MbedTlsObj::TlsConfig::BasicInit();

	int endpoint = isServer ? MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT;

	if (!MbedTlsObj::TlsConfig::operator bool() || //Make sure basic init is successful.
		!m_prvKey || !*m_prvKey || //Make sure private exists.
		!m_cert || !*m_cert || //Make sure cert exists.
		mbedtls_ssl_config_defaults(GetInternalPtr(), endpoint, MBEDTLS_SSL_TRANSPORT_STREAM,
			MBEDTLS_SSL_PRESET_SUITEB) != MBEDTLS_SUCCESS_RET || //Setup config default.
		mbedtls_ssl_conf_own_cert(GetInternalPtr(), m_cert->GetInternalPtr(),
			m_prvKey->GetInternalPtr()) != MBEDTLS_SUCCESS_RET //Setup own certificate.
		)
	{
		MbedTlsObj::TlsConfig::Destroy();
		return;
	}

	mbedtls_ssl_conf_ca_chain(GetInternalPtr(), m_cert->GetInternalPtr(), nullptr);
	mbedtls_ssl_conf_authmode(GetInternalPtr(), MBEDTLS_SSL_VERIFY_REQUIRED);
}

TlsConfig::TlsConfig(TlsConfig && other) :
	MbedTlsObj::TlsConfig(std::forward<TlsConfig>(other)),
	m_prvKey(std::move(other.m_prvKey)),
	m_cert(std::move(other.m_cert)),
	m_expectedAppName(std::move(other.m_expectedAppName))
{
	if (*this)
	{
		mbedtls_ssl_conf_verify(m_ptr, &TlsConfig::CertVerifyCallBack, this);
	}
}

TlsConfig & TlsConfig::operator=(TlsConfig && other)
{
	if (this != &other)
	{
		MbedTlsObj::TlsConfig::operator=(std::forward<MbedTlsObj::TlsConfig>(other));
		m_prvKey = std::move(other.m_prvKey);
		m_cert = std::move(other.m_cert);
		m_expectedAppName = std::move(other.m_expectedAppName);

		if (*this)
		{
			mbedtls_ssl_conf_verify(m_ptr, &TlsConfig::CertVerifyCallBack, this);
		}
	}
	return *this;
}

void TlsConfig::Destroy()
{
	m_prvKey.reset();
	m_cert.reset();
}

TlsConfig::TlsConfig(mbedtls_ssl_config * ptr) :
	MbedTlsObj::TlsConfig(ptr)
{
	if (*this)
	{
		mbedtls_ssl_conf_verify(m_ptr, &TlsConfig::CertVerifyCallBack, this);
	}
}
