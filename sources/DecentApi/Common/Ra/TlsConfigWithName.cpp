#include "TlsConfigWithName.h"

#include <mbedtls/ssl.h>

#include "States.h"
#include "Crypto.h"
#include "AppX509Cert.h"
#include "WhiteList/LoadedList.h"

#include "../Common.h"

using namespace Decent::MbedTlsObj;
using namespace Decent::Ra;

TlsConfigWithName::TlsConfigWithName(States & state, Mode cntMode, const std::string& expectedAppName, std::shared_ptr<SessionTicketMgrBase> ticketMgr) :
	TlsConfigBase(state, cntMode, ticketMgr),
	m_expectedAppName(expectedAppName)
{
}

TlsConfigWithName::TlsConfigWithName(TlsConfigWithName && rhs) :
	TlsConfigBase(std::forward<TlsConfigBase>(rhs)),
	m_expectedAppName(std::move(rhs.m_expectedAppName))
{
}

TlsConfigWithName::~TlsConfigWithName()
{
}

int TlsConfigWithName::VerifyDecentAppCert(const AppX509Cert & cert, int depth, uint32_t & flag) const
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
		PRINT_I("Peer's AuthList does not match.\n\tPeer's AuthList %s.\n\tOur AuthList: %s.", cert.GetWhiteList().c_str(), m_expectedAppName.c_str());
		flag = MBEDTLS_X509_BADCERT_NOT_TRUSTED;
		return MBEDTLS_SUCCESS_RET;
	}

	return MBEDTLS_SUCCESS_RET;
}
