#include "TlsConfig.h"

#include <mbedtls/ssl.h>

#include "../States.h"
#include "../WhiteList/HardCoded.h"
#include "../WhiteList/Loaded.h"

#include "Crypto.h"

using namespace Decent::Ra::Verifier;

namespace
{
	static constexpr int MBEDTLS_SUCCESS_RET = 0;
}

TlsConfig::TlsConfig(const std::string & expectedAppName, const std::string & expectedVerifierName, bool isServer) :
	Decent::Ra::TlsConfig(expectedVerifierName, isServer),
	m_expectedVerifiedAppName(expectedAppName)
{
}

TlsConfig::TlsConfig(Decent::Ra::Verifier::TlsConfig&& other) :
	Decent::Ra::TlsConfig(std::forward<Decent::Ra::Verifier::TlsConfig>(other)),
	m_expectedVerifiedAppName(std::move(other.m_expectedVerifiedAppName))
{
}

TlsConfig& TlsConfig::operator=(Decent::Ra::Verifier::TlsConfig&& other)
{
	if (this != &other)
	{
		Decent::Ra::TlsConfig::operator=(std::forward<Decent::Ra::TlsConfig>(other));
		
		m_expectedVerifiedAppName = std::move(other.m_expectedVerifiedAppName);
	}
	return *this;
}

int TlsConfig::CertVerifyCallBack(mbedtls_x509_crt * cert, int depth, uint32_t * flag) const
{
	switch (depth)
	{
	case 0: //App Cert
	{
		Decent::Ra::Verifier::AppX509 appCert(cert);
		if (!appCert)
		{
			*flag = MBEDTLS_X509_BADCERT_NOT_TRUSTED;
			return MBEDTLS_SUCCESS_RET;
		}

		return AppCertVerifyCallBack(appCert, depth, *flag);
	}
	case 1: //Verifier Cert
	{
		Decent::Ra::AppX509 verifierCert(cert);
		if (!verifierCert)
		{
			*flag = MBEDTLS_X509_BADCERT_NOT_TRUSTED;
			return MBEDTLS_SUCCESS_RET;
		}

		return AppCertVerifyCallBack(verifierCert, depth, *flag);
	}
	case 2: //Decent Cert
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

int TlsConfig::AppCertVerifyCallBack(const Decent::Ra::AppX509 & cert, int depth, uint32_t & flag) const
{
	using namespace Decent::Ra::WhiteList;

	if (flag != MBEDTLS_SUCCESS_RET)
	{//App cert is invalid!
		return MBEDTLS_SUCCESS_RET;
	}

	//Check Loaded Lists are match!!
	StaticTypeList peerLoadedList(Loaded::ParseWhiteListFromJson(cert.GetWhiteList()));
	if (!(States::Get().GetLoadedWhiteList() >= peerLoadedList))
	{
		flag = MBEDTLS_X509_BADCERT_NOT_TRUSTED;
		return MBEDTLS_SUCCESS_RET;
	}

	//Check peer's hash is in the white list.
	std::string peerHash = Decent::Ra::GetHashFromAppId(cert.GetPlatformType(), cert.GetAppId());
	if (!States::Get().GetHardCodedWhiteList().CheckHashAndName(peerHash, GetExpectedAppName()) &&
		!States::Get().GetLoadedWhiteList().CheckHashAndName(peerHash, GetExpectedAppName()))
	{
		flag = MBEDTLS_X509_BADCERT_NOT_TRUSTED;
		return MBEDTLS_SUCCESS_RET;
	}

	return MBEDTLS_SUCCESS_RET;
}

int TlsConfig::AppCertVerifyCallBack(const Decent::Ra::Verifier::AppX509& cert, int depth, uint32_t& flag) const
{
	using namespace Decent::Ra::WhiteList;

	if (flag != MBEDTLS_SUCCESS_RET)
	{//App cert is invalid!
		return MBEDTLS_SUCCESS_RET;
	}

	//Check Loaded Lists are match!!
	StaticTypeList peerLoadedList(Loaded::ParseWhiteListFromJson(cert.GetWhiteList()));
	if (States::Get().GetLoadedWhiteList() != peerLoadedList)
	{
		flag = MBEDTLS_X509_BADCERT_NOT_TRUSTED;
		return MBEDTLS_SUCCESS_RET;
	}

	//Check peer's common name is same as expected.
	if (cert.GetCommonName() != m_expectedVerifiedAppName)
	{
		flag = MBEDTLS_X509_BADCERT_NOT_TRUSTED;
		return MBEDTLS_SUCCESS_RET;
	}

	return MBEDTLS_SUCCESS_RET;
}
