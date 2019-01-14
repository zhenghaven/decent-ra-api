#include "DecentCrypto.h"

#include <climits>

#include <mbedtls/x509_csr.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/ssl.h>

#include "CommonTool.h"
#include "DecentStates.h"
#include "MbedTlsHelpers.h"
#include "CryptoKeyContainer.h"
#include "DecentCertContainer.h"
#include "DecentRAReport.h"

using namespace Decent;

const mbedtls_x509_crt_profile & Decent::Crypto::GetX509Profile()
{
	static const mbedtls_x509_crt_profile inst = {
		mbedtls_md_type_t::MBEDTLS_MD_SHA256,
		mbedtls_pk_type_t::MBEDTLS_PK_ECKEY,
		mbedtls_ecp_group_id::MBEDTLS_ECP_DP_SECP256R1,
		UINT32_MAX
	};
	
	return inst;
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
		std::pair<std::string, std::pair<bool, std::string> >(Decent::Crypto::X509ExtPlatformTypeOid, std::pair<bool, std::string>(false, platformType)),
		std::pair<std::string, std::pair<bool, std::string> >(Decent::Crypto::X509ExtSelfRaReportOid, std::pair<bool, std::string>(false, selfRaReport)),
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
		std::pair<std::string, std::pair<bool, std::string> >(Decent::Crypto::X509ExtPlatformTypeOid, std::pair<bool, std::string>(false, std::string())),
		std::pair<std::string, std::pair<bool, std::string> >(Decent::Crypto::X509ExtSelfRaReportOid, std::pair<bool, std::string>(false, std::string())),
	};

	if (GetExtensions(extMap))
	{
		m_platformType.swap(extMap[Decent::Crypto::X509ExtPlatformTypeOid].second);
		m_selfRaReport.swap(extMap[Decent::Crypto::X509ExtSelfRaReportOid].second);
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
	return MbedTlsObj::X509Cert::operator bool() && m_ecPubKey;
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
	const std::string & enclaveHash, const std::string & platformType, const std::string & appId) :
	MbedTlsObj::X509Cert(caCert, serverPrvKey, pubKey, MbedTlsObj::BigNumber::GenRandomNumber(GENERAL_256BIT_32BYTE_SIZE), LONG_MAX, true, -1,
		MBEDTLS_X509_KU_NON_REPUDIATION | MBEDTLS_X509_KU_DIGITAL_SIGNATURE | MBEDTLS_X509_KU_KEY_AGREEMENT | MBEDTLS_X509_KU_KEY_CERT_SIGN | MBEDTLS_X509_KU_CRL_SIGN,
		MBEDTLS_X509_NS_CERT_TYPE_SSL_CA | MBEDTLS_X509_NS_CERT_TYPE_SSL_CLIENT | MBEDTLS_X509_NS_CERT_TYPE_SSL_SERVER,
		("CN=" + enclaveHash).c_str(),
		std::map<std::string, std::pair<bool, std::string> >{
		std::pair<std::string, std::pair<bool, std::string> >(Decent::Crypto::X509ExtPlatformTypeOid, std::pair<bool, std::string>(false, platformType)),
		std::pair<std::string, std::pair<bool, std::string> >(Decent::Crypto::X509ExtLaIdentityOid, std::pair<bool, std::string>(false, appId)),
	}
	),
	m_platformType(platformType),
	m_appId(appId),
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
	return MbedTlsObj::X509Cert::operator bool() && m_ecPubKey;
}

const std::string & AppX509::GetPlatformType() const
{
	return m_platformType;
}

const std::string & AppX509::GetAppId() const
{
	return m_appId;
}

const MbedTlsObj::ECKeyPublic & AppX509::GetEcPublicKey() const
{
	return m_ecPubKey;
}

void AppX509::ParseExtensions()
{
	std::map<std::string, std::pair<bool, std::string> > extMap =
	{
		std::pair<std::string, std::pair<bool, std::string> >(Decent::Crypto::X509ExtPlatformTypeOid, std::pair<bool, std::string>(false, std::string())),
		std::pair<std::string, std::pair<bool, std::string> >(Decent::Crypto::X509ExtLaIdentityOid, std::pair<bool, std::string>(false, std::string())),
	};

	if (GetExtensions(extMap))
	{
		m_platformType.swap(extMap[Decent::Crypto::X509ExtPlatformTypeOid].second);
		m_appId.swap(extMap[Decent::Crypto::X509ExtLaIdentityOid].second);
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

int TlsConfig::CertVerifyCallBack(mbedtls_x509_crt * cert, int depth, uint32_t * flag)
{
	switch (depth)
	{
	case 0: //App Cert
	{
		//if (!m_appCertVerifier)
		//{
		//	return MBEDTLS_ERR_X509_FATAL_ERROR;
		//}

		AppX509 appCert(cert);

		//*flag |= ((appCert && 
		//	m_appCertVerifier(appCert.GetEcPublicKey(), appCert.GetPlatformType(), appCert.GetAppId())) ? 0 :
		//	MBEDTLS_X509_BADCERT_NOT_TRUSTED);
		COMMON_PRINTF("TLS callback app cert: \n %s \n", appCert.ToPemString().c_str());

		*flag = 0;

		return 0;
	}
	case 1: //Decent Cert
	{
		//std::shared_ptr<const ServerX509> decentCert = DecentCertContainer::Get().GetServerCert();
		//if (decentCert && decentCert.get()->GetInternalPtr() == cert)
		//{
		//	*flag = 0;
		//	return 0; //In most case, should return at here.
		//}
		
		//if (!m_decentCertVerifier)
		//{
		//	return MBEDTLS_ERR_X509_FATAL_ERROR;
		//}

		ServerX509 serverCert(cert);
		COMMON_PRINTF("TLS callback server cert: \n %s \n", serverCert.ToPemString().c_str());

		*flag = 0;
		
		return 0;
	}
	default:
		return MBEDTLS_ERR_X509_FATAL_ERROR;
	}
}

TlsConfig::TlsConfig(Decent::Crypto::AppIdVerfier appIdVerifier, bool isServer) :
	Decent::TlsConfig(ConstructTlsConfig(isServer))
{
	m_appCertVerifier.swap(appIdVerifier);
}

TlsConfig::TlsConfig(TlsConfig && other) :
	MbedTlsObj::TlsConfig(std::forward<TlsConfig>(other)),
	m_prvKey(std::move(other.m_prvKey)),
	m_cert(std::move(other.m_cert)),
	m_decentCert(std::move(other.m_decentCert)),
	m_appCertVerifier(std::move(other.m_appCertVerifier))
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
		m_decentCert = std::move(other.m_decentCert);
		m_appCertVerifier = std::move(other.m_appCertVerifier);

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
	m_decentCert.reset();
}

Decent::TlsConfig TlsConfig::ConstructTlsConfig(bool isServer)
{
	Decent::TlsConfig config(new mbedtls_ssl_config);
	config.BasicInit();

	//config.m_decentCert = DecentCertContainer::Get().GetServerCert();
	config.m_prvKey = CryptoKeyContainer::GetInstance().GetSignKeyPair();
	config.m_cert = Decent::States::Get().GetCertContainer().GetCert();

	if (//!config.m_decentCert || !*config.m_decentCert ||
		mbedtls_ssl_config_defaults(config.GetInternalPtr(), isServer ? MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT, 
		MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_SUITEB) != 0)
	{
		config.Destroy();
		return config;
	}

	if (config.m_prvKey && *config.m_prvKey && config.m_cert && *config.m_cert &&
		mbedtls_ssl_conf_own_cert(config.GetInternalPtr(), config.m_cert->GetInternalPtr(),
		config.m_prvKey->GetInternalPtr()) != 0)
	{
		config.Destroy();
		return config;
	}
	
	mbedtls_ssl_conf_ca_chain(config.GetInternalPtr(), config.m_cert->GetInternalPtr(), nullptr);
	mbedtls_ssl_conf_authmode(config.GetInternalPtr(), MBEDTLS_SSL_VERIFY_REQUIRED);

	return config;
}

TlsConfig::TlsConfig(mbedtls_ssl_config * ptr) :
	MbedTlsObj::TlsConfig(ptr)
{
	if (*this)
	{
		mbedtls_ssl_conf_verify(m_ptr, &TlsConfig::CertVerifyCallBack, this);
	}
}
