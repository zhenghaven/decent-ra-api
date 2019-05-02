#include "TlsConfig.h"

#include <mbedtls/ssl.h>

#include "../States.h"
#include "../WhiteList/LoadedList.h"

#include "Crypto.h"

using namespace Decent::Ra::Verifier;

TlsConfig::TlsConfig(Decent::Ra::States& state, Mode cntMode, const std::string& expectedVerifierName, const std::string & expectedAppName) :
	Decent::Ra::TlsConfigWithName(state, cntMode, expectedVerifierName),
	m_expectedVerifiedAppName(expectedAppName)
{
}

TlsConfig::TlsConfig(TlsConfig&& other) :
	Decent::Ra::TlsConfigWithName(std::forward<Decent::Ra::TlsConfigWithName>(other)),
	m_expectedVerifiedAppName(std::move(other.m_expectedVerifiedAppName))
{}

int TlsConfig::VerifyCert(mbedtls_x509_crt& cert, int depth, uint32_t& flag) const
{
	using namespace Decent::MbedTlsObj;

	switch (depth)
	{
	case 0: //Decent App Cert
	{
		Decent::Ra::Verifier::AppX509 appCert(cert);
		if (!appCert)
		{
			flag = MBEDTLS_X509_BADCERT_NOT_TRUSTED;
			return MBEDTLS_SUCCESS_RET;
		}

		return VerifyDecentVerifiedAppCert(appCert, depth, flag);
	}
	case 1: //Decent Verifier Cert
	{
		Decent::Ra::AppX509 verifierCert(cert);
		if (!verifierCert)
		{
			flag = MBEDTLS_X509_BADCERT_NOT_TRUSTED;
			return MBEDTLS_SUCCESS_RET;
		}

		return VerifyDecentAppCert(verifierCert, depth, flag);
	}
	case 2: //Decent Server Cert
	{
		const ServerX509 serverCert(cert);
		if (!serverCert)
		{
			flag = MBEDTLS_X509_BADCERT_NOT_TRUSTED;
			return MBEDTLS_SUCCESS_RET;
		}

		return VerifyDecentServerCert(serverCert, depth, flag);
	}
	default:
		return MBEDTLS_ERR_X509_FATAL_ERROR;
	}
}

int TlsConfig::VerifyDecentAppCert(const Decent::Ra::AppX509 & cert, int depth, uint32_t & flag) const
{
	using namespace Decent::Ra::WhiteList;
	using namespace Decent::MbedTlsObj;

	if (flag != MBEDTLS_SUCCESS_RET)
	{//App cert is invalid! Directly return.
		return MBEDTLS_SUCCESS_RET;
	}

	//Check peer's hash is in the white list, and the app name is matched.
	std::string peerHash = Decent::Ra::GetHashFromAppId(cert.GetPlatformType(), cert.GetAppId());
	if (!GetState().GetLoadedWhiteList().CheckHashAndName(peerHash, GetExpectedAppName()))
	{
		flag = MBEDTLS_X509_BADCERT_NOT_TRUSTED;
		return MBEDTLS_SUCCESS_RET;
	}

	//Check Loaded Lists are equivalent
	StaticList peerLoadedList(LoadedList::ParseWhiteListFromJson(cert.GetWhiteList()));
	if (peerLoadedList <= GetState().GetLoadedWhiteList())
	{
		flag = MBEDTLS_X509_BADCERT_NOT_TRUSTED;
		return MBEDTLS_SUCCESS_RET;
	}

	return MBEDTLS_SUCCESS_RET;
}

int TlsConfig::VerifyDecentVerifiedAppCert(const Decent::Ra::Verifier::AppX509& cert, int depth, uint32_t& flag) const
{
	using namespace Decent::Ra::WhiteList;
	using namespace Decent::MbedTlsObj;

	if (flag != MBEDTLS_SUCCESS_RET)
	{//App cert is invalid! Directly return.
		return MBEDTLS_SUCCESS_RET;
	}

	//Check Loaded Lists are equivalent
	StaticList peerLoadedList(LoadedList::ParseWhiteListFromJson(cert.GetWhiteList()));
	if (GetState().GetLoadedWhiteList() != peerLoadedList)
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
