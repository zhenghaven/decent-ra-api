#include "TlsConfigAnyWhiteListed.h"

#include <mbedtls/ssl.h>

#include "States.h"
#include "Crypto.h"
#include "AppX509Cert.h"
#include "WhiteList/LoadedList.h"

using namespace Decent::Ra;
using namespace Decent::MbedTlsObj;

int TlsConfigAnyWhiteListed::VerifyDecentAppCert(const AppX509Cert & cert, int depth, uint32_t & flag) const
{
	using namespace Decent::Ra::WhiteList;

	if (flag != MBEDTLS_SUCCESS_RET)
	{//App cert is invalid! Directly return.
		return MBEDTLS_SUCCESS_RET;
	}

	//Check peer's hash is in the white list, while the app name is ignored.
	std::string peerHash = GetHashFromAppId(cert.GetPlatformType(), cert.GetAppId());
	std::string appName;
	if (!GetState().GetLoadedWhiteList().CheckHash(peerHash, appName))
	{
		flag = MBEDTLS_X509_BADCERT_NOT_TRUSTED;
		return MBEDTLS_SUCCESS_RET;
	}

	//Check Loaded Lists are equivalent
	StaticList peerLoadedList(LoadedList::ParseWhiteListFromJson(cert.GetWhiteList()));
	if (peerLoadedList != GetState().GetLoadedWhiteList())
	{
		flag = MBEDTLS_X509_BADCERT_NOT_TRUSTED;
		return MBEDTLS_SUCCESS_RET;
	}

	return MBEDTLS_SUCCESS_RET;
}
