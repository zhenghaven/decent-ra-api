#include "TlsConfigWithName.h"

#include <mbedtls/ssl.h>

#include "Crypto.h"
#include "States.h"
#include "WhiteList/LoadedList.h"

using namespace Decent::MbedTlsObj;
using namespace Decent::Ra;

TlsConfigWithName::TlsConfigWithName(States & state, Mode cntMode, const std::string& expectedAppName, std::shared_ptr<SessionTicketMgrBase> ticketMgr) :
	TlsConfig(state, cntMode, ticketMgr),
	m_expectedAppName(expectedAppName)
{
}

TlsConfigWithName::TlsConfigWithName(TlsConfigWithName && rhs) :
	TlsConfig(std::forward<TlsConfig>(rhs)),
	m_expectedAppName(std::move(rhs.m_expectedAppName))
{
}

TlsConfigWithName::~TlsConfigWithName()
{
}

int TlsConfigWithName::VerifyDecentAppCert(const AppX509 & cert, int depth, uint32_t & flag) const
{
	using namespace Decent::Ra::WhiteList;
	using namespace Decent::MbedTlsObj;

	if (flag != MBEDTLS_SUCCESS_RET)
	{//App cert is invalid! Directly return.
		return MBEDTLS_SUCCESS_RET;
	}

	//Check peer's hash is in the white list, and the app name is matched.
	std::string peerHash = Decent::Ra::GetHashFromAppId(cert.GetPlatformType(), cert.GetAppId());
	if (!GetState().GetLoadedWhiteList().CheckHashAndName(peerHash, m_expectedAppName))
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
