#include "TlsConfig.h"

#include <mbedtls/ssl.h>

#include "Crypto.h"
#include "States.h"
#include "KeyContainer.h"
#include "CertContainer.h"
#include "WhiteList/DecentServer.h"

#include "../MbedTls/MbedTlsException.h"
#include "../Common.h"

using namespace Decent::Ra;

#define CHECK_MBEDTLS_RET(VAL, FUNCSTR) {int retVal = VAL; if(retVal != Decent::MbedTlsObj::MBEDTLS_SUCCESS_RET) { throw Decent::MbedTlsObj::MbedTlsException(#FUNCSTR, retVal); } }

TlsConfig::TlsConfig(States& state, Mode cntMode) :
	MbedTlsObj::TlsConfig(),
	m_state(state),
	m_prvKey(m_state.GetKeyContainer().GetSignKeyPair()),
	m_cert(m_state.GetCertContainer().GetCert())
{
	int endpoint = 0;
	switch (cntMode)
	{
	case Mode::ServerVerifyPeer:
	case Mode::ServerNoVerifyPeer:
		endpoint = MBEDTLS_SSL_IS_SERVER;
		break;
	case Mode::ClientHasCert:
	case Mode::ClientNoCert:
		endpoint = MBEDTLS_SSL_IS_CLIENT;
		break;
	default:
		throw Decent::RuntimeException("An unexpected TLS connection mode is given.");
	}

	CHECK_MBEDTLS_RET(mbedtls_ssl_config_defaults(Get(), endpoint, MBEDTLS_SSL_TRANSPORT_STREAM,
		MBEDTLS_SSL_PRESET_SUITEB), TlsConfig::TlsConfig);


	switch (cntMode)
	{
	case Mode::ServerVerifyPeer: //Usually in Decent RA, server side always has certificate.
	case Mode::ServerNoVerifyPeer:
	case Mode::ClientHasCert:
		if (!m_prvKey || !*m_prvKey || !m_cert || !*m_cert)
		{
			throw Decent::RuntimeException("Key or certificate stored in the global state are invalid.");
		}
		CHECK_MBEDTLS_RET(mbedtls_ssl_conf_own_cert(Get(), m_cert->Get(), m_prvKey->Get()), TlsConfig::TlsConfig);
		break;
	case Mode::ClientNoCert:
	default:
		break;
	}

	switch (cntMode)
	{
	case Mode::ServerNoVerifyPeer:
		mbedtls_ssl_conf_authmode(Get(), MBEDTLS_SSL_VERIFY_NONE);
		break;
	case Mode::ServerVerifyPeer:
	case Mode::ClientHasCert: //Usually in Decent RA, client side always verify server side.
	case Mode::ClientNoCert:
		if (!m_cert || !*m_cert)
		{
			throw Decent::RuntimeException("Key or certificate stored in the global state are invalid.");
		}
		mbedtls_ssl_conf_ca_chain(Get(), m_cert->Get(), nullptr);
		mbedtls_ssl_conf_authmode(Get(), MBEDTLS_SSL_VERIFY_REQUIRED);
	default:
		break;
	}
}

TlsConfig::TlsConfig(TlsConfig && other) :
	MbedTlsObj::TlsConfig(std::forward<MbedTlsObj::TlsConfig>(other)),
	m_state(other.m_state),
	m_prvKey(std::move(other.m_prvKey)),
	m_cert(std::move(other.m_cert))
{
}

TlsConfig::~TlsConfig()
{
}

int TlsConfig::VerifyCert(mbedtls_x509_crt& cert, int depth, uint32_t& flag) const
{
	switch (depth)
	{
	case 0: //Decent App Cert
	{
		AppX509 appCert(cert);
		if (!appCert)
		{
			flag = MBEDTLS_X509_BADCERT_NOT_TRUSTED;
			return Decent::MbedTlsObj::MBEDTLS_SUCCESS_RET;
		}

		//LOGI("Verifing App Cert: %s.", appCert.GetCommonName().c_str());
		return VerifyDecentAppCert(appCert, depth, flag);
	}
	case 1: //Decent Server Cert
	{
		const ServerX509 serverCert(cert);
		if (!serverCert)
		{
			flag = MBEDTLS_X509_BADCERT_NOT_TRUSTED;
			return Decent::MbedTlsObj::MBEDTLS_SUCCESS_RET;
		}

		//LOGI("Verifing Server Cert: %s.", serverCert.GetCommonName().c_str());
		return VerifyDecentServerCert(serverCert, depth, flag);
	}
	default:
		return MBEDTLS_ERR_X509_FATAL_ERROR;
	}
}

int TlsConfig::VerifyDecentServerCert(const ServerX509 & cert, int depth, uint32_t & flag) const
{
	using namespace Decent::MbedTlsObj;

	const bool verifyRes = m_state.GetServerWhiteList().AddTrustedNode(cert);
	flag = verifyRes ? MBEDTLS_SUCCESS_RET : MBEDTLS_X509_BADCERT_NOT_TRUSTED;
	return MBEDTLS_SUCCESS_RET;
}
