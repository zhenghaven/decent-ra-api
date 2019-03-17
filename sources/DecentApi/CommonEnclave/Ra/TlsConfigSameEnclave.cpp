#include "TlsConfigSameEnclave.h"

#include <mbedtls/ssl.h>

#include "../../Common/Ra/Crypto.h"
#include "../../Common/Ra/States.h"
#include "../../Common/Ra/WhiteList/Loaded.h"

#include "../Tools/Crypto.h"

using namespace Decent::Ra;
using namespace Decent::Tools;

int TlsConfigSameEnclave::VerifyDecentAppCert(const AppX509 & cert, int depth, uint32_t & flag) const
{
	using namespace Decent::Ra::WhiteList;
	using namespace Decent::MbedTlsObj;

	if (flag != MBEDTLS_SUCCESS_RET)
	{//App cert is invalid! Directly return.
		return MBEDTLS_SUCCESS_RET;
	}

	//Check peer's hash is same as self's hash.
	std::string peerHash = Decent::Ra::GetHashFromAppId(cert.GetPlatformType(), cert.GetAppId());
	if (GetSelfHashBase64() != peerHash)
	{
		flag = MBEDTLS_X509_BADCERT_NOT_TRUSTED;
		return MBEDTLS_SUCCESS_RET;
	}

	//Check Loaded Lists are equivalent
	StaticTypeList peerLoadedList(Loaded::ParseWhiteListFromJson(cert.GetWhiteList()));
	if (peerLoadedList != GetState().GetLoadedWhiteList())
	{
		flag = MBEDTLS_X509_BADCERT_NOT_TRUSTED;
		return MBEDTLS_SUCCESS_RET;
	}

	return MBEDTLS_SUCCESS_RET;
}