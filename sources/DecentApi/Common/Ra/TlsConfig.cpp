#include "TlsConfig.h"

#include <mbedtls/ssl.h>

#include "Crypto.h"
#include "States.h"
#include "KeyContainer.h"
#include "CertContainer.h"
#include "WhiteList/DecentServer.h"
#include "WhiteList/HardCoded.h"
#include "WhiteList/Loaded.h"

using namespace Decent::Ra;

namespace
{
	static constexpr int MBEDTLS_SUCCESS_RET = 0;
}

int TlsConfig::CertVerifyCallBack(void * inst, mbedtls_x509_crt * cert, int depth, uint32_t * flag)
{
	if (!inst || !cert || !flag)
	{
		return MBEDTLS_ERR_X509_FATAL_ERROR;
	}
	return static_cast<TlsConfig*>(inst)->CertVerifyCallBack(*cert, depth, *flag);
}

int TlsConfig::CertVerifyCallBack(mbedtls_x509_crt& cert, int depth, uint32_t& flag) const
{
	switch (depth)
	{
	case 0: //App Cert
	{
		AppX509 appCert(cert);
		if (!appCert)
		{
			flag = MBEDTLS_X509_BADCERT_NOT_TRUSTED;
			return MBEDTLS_SUCCESS_RET;
		}

		return AppCertVerifyCallBack(appCert, depth, flag);
	}
	case 1: //Decent Cert
	{
		const ServerX509 serverCert(cert);
		if (!serverCert)
		{
			flag = MBEDTLS_X509_BADCERT_NOT_TRUSTED;
			return MBEDTLS_SUCCESS_RET;
		}

		return ServerCertVerifyCallBack(serverCert, depth, flag);
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
	if (peerLoadedList != m_state.GetLoadedWhiteList())
	{
		flag = MBEDTLS_X509_BADCERT_NOT_TRUSTED;
		return MBEDTLS_SUCCESS_RET;
	}

	//Check peer's hash is in the white list.
	std::string peerHash = Decent::Ra::GetHashFromAppId(cert.GetPlatformType(), cert.GetAppId());
	if (!m_state.GetHardCodedWhiteList().CheckHashAndName(peerHash, m_expectedAppName) &&
		!m_state.GetLoadedWhiteList().CheckHashAndName(peerHash, m_expectedAppName))
	{
		flag = MBEDTLS_X509_BADCERT_NOT_TRUSTED;
		return MBEDTLS_SUCCESS_RET;
	}

	return MBEDTLS_SUCCESS_RET;
}

int TlsConfig::ServerCertVerifyCallBack(const ServerX509 & cert, int depth, uint32_t & flag) const
{
	const bool verifyRes = m_state.GetServerWhiteList().AddTrustedNode(cert);
	flag = verifyRes ? MBEDTLS_SUCCESS_RET : MBEDTLS_X509_BADCERT_NOT_TRUSTED;
	return MBEDTLS_SUCCESS_RET;
}

TlsConfig::TlsConfig(const std::string& expectedAppName, States& state, bool isServer) :
	MbedTlsObj::TlsConfig(),
	m_state(state),
	m_prvKey(m_state.GetKeyContainer().GetSignKeyPair()),
	m_cert(m_state.GetCertContainer().GetCert()),
	m_expectedAppName(expectedAppName)
{
	int endpoint = isServer ? MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT;

	if (!MbedTlsObj::TlsConfig::operator bool() || //Make sure basic init is successful.
		!m_prvKey || !*m_prvKey || //Make sure private exists.
		!m_cert || !*m_cert || //Make sure cert exists.
		mbedtls_ssl_config_defaults(Get(), endpoint, MBEDTLS_SSL_TRANSPORT_STREAM,
			MBEDTLS_SSL_PRESET_SUITEB) != MBEDTLS_SUCCESS_RET || //Setup config default.
		mbedtls_ssl_conf_own_cert(Get(), m_cert->Get(),
			m_prvKey->Get()) != MBEDTLS_SUCCESS_RET //Setup own certificate.
		)
	{
		m_prvKey.reset();
		m_cert.reset();
		return;
	}

	mbedtls_ssl_conf_ca_chain(Get(), m_cert->Get(), nullptr);
	mbedtls_ssl_conf_authmode(Get(), MBEDTLS_SSL_VERIFY_REQUIRED);
}

TlsConfig::TlsConfig(TlsConfig && other) :
	MbedTlsObj::TlsConfig(std::forward<TlsConfig>(other)),
	m_state(other.m_state),
	m_prvKey(std::move(other.m_prvKey)),
	m_cert(std::move(other.m_cert)),
	m_expectedAppName(std::move(other.m_expectedAppName))
{
	if (*this)
	{
		mbedtls_ssl_conf_verify(Get(), &TlsConfig::CertVerifyCallBack, this);
	}
}

TlsConfig & TlsConfig::operator=(TlsConfig && other)
{
	MbedTlsObj::TlsConfig::operator=(std::forward<MbedTlsObj::TlsConfig>(other));
	if (this != &other)
	{
		m_prvKey = std::move(other.m_prvKey);
		m_cert = std::move(other.m_cert);
		m_expectedAppName = std::move(other.m_expectedAppName);

		if (*this)
		{
			mbedtls_ssl_conf_verify(Get(), &TlsConfig::CertVerifyCallBack, this);
		}
	}
	return *this;
}
