#include "TlsConfigWithVerifier.h"

#include <mbedtls/ssl.h>

#include "States.h"
#include "Crypto.h"
#include "ServerX509Cert.h"
#include "VerifiedAppX509Cert.h"
#include "WhiteList/LoadedList.h"

using namespace Decent::Ra;

TlsConfigWithVerifier::TlsConfigWithVerifier(Decent::Ra::States& state, Mode cntMode, const std::string& expectedVerifierName, const std::string & expectedAppName, std::shared_ptr<Decent::MbedTlsObj::SessionTicketMgrBase> ticketMgr) :
	Decent::Ra::TlsConfigWithName(state, cntMode, expectedVerifierName, ticketMgr),
	m_expectedVerifiedAppName(expectedAppName)
{
}

TlsConfigWithVerifier::TlsConfigWithVerifier(TlsConfigWithVerifier&& other) :
	Decent::Ra::TlsConfigWithName(std::forward<Decent::Ra::TlsConfigWithName>(other)),
	m_expectedVerifiedAppName(std::move(other.m_expectedVerifiedAppName))
{}

int TlsConfigWithVerifier::VerifyCert(mbedtls_x509_crt& cert, int depth, uint32_t& flag) const
{
	using namespace Decent::MbedTlsObj;

	switch (depth)
	{
	case 0: //Decent App Cert
	{
		VerifiedAppX509Cert appCert(cert);

		return VerifyDecentVerifiedAppCert(appCert, depth, flag);
	}
	case 1: //Decent Verifier Cert
	{
		AppX509Cert verifierCert(cert);

		return VerifyDecentAppCert(verifierCert, depth, flag);
	}
	case 2: //Decent Server Cert
	{
		const ServerX509Cert serverCert(cert);

		return VerifyDecentServerCert(serverCert, depth, flag);
	}
	default:
		return MBEDTLS_ERR_X509_FATAL_ERROR;
	}
}

int TlsConfigWithVerifier::VerifyDecentAppCert(const AppX509Cert & cert, int depth, uint32_t & flag) const
{
	using namespace Decent::Ra::WhiteList;
	using namespace Decent::MbedTlsObj;

	if (flag != MBEDTLS_SUCCESS_RET)
	{//App cert is invalid! Directly return.
		return MBEDTLS_SUCCESS_RET;
	}

	//Check peer's hash is in the white list, and the app name is matched.
	std::string peerHash = GetHashFromAppId(cert.GetPlatformType(), cert.GetAppId());
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

int TlsConfigWithVerifier::VerifyDecentVerifiedAppCert(const VerifiedAppX509Cert& cert, int depth, uint32_t& flag) const
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
	if (cert.GetCurrCommonName() != m_expectedVerifiedAppName)
	{
		flag = MBEDTLS_X509_BADCERT_NOT_TRUSTED;
		return MBEDTLS_SUCCESS_RET;
	}

	return MBEDTLS_SUCCESS_RET;
}
