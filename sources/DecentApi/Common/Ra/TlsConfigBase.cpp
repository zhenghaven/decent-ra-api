#include "TlsConfigBase.h"

#include <mbedtls/ssl.h>

#include "../make_unique.h"
#include "../MbedTls/Drbg.h"
#include "../MbedTls/EcKey.h"

#include "States.h"
#include "AppX509Cert.h"
#include "ServerX509Cert.h"
#include "KeyContainer.h"
#include "CertContainer.h"
#include "WhiteList/DecentServer.h"

using namespace Decent::Ra;
using namespace Decent::Tools;
using namespace Decent::MbedTlsObj;

TlsConfigBase::TlsConfigBase(States& state, Mode cntMode, std::shared_ptr<SessionTicketMgrBase> ticketMgr) :
	TlsConfig(true, cntMode, MBEDTLS_SSL_PRESET_SUITEB, make_unique<Decent::MbedTlsObj::Drbg>(),
		state.GetCertContainer().GetCert(), state.GetCertContainer().GetCert(), state.GetKeyContainer().GetSignKeyPair(),
		ticketMgr),
	m_state(state)
{
}

TlsConfigBase::TlsConfigBase(TlsConfigBase && rhs) :
	TlsConfig(std::forward<TlsConfig>(rhs)),
	m_state(rhs.m_state)
{
}

TlsConfigBase::~TlsConfigBase()
{
}

int TlsConfigBase::VerifyCert(mbedtls_x509_crt& cert, int depth, uint32_t& flag) const
{
	switch (depth)
	{
	case 0: //Decent App Cert
	{
		AppX509Cert appCert(cert);

		return VerifyDecentAppCert(appCert, depth, flag);
	}
	case 1: //Decent Server Cert
	{
		const ServerX509Cert serverCert(cert);

		return VerifyDecentServerCert(serverCert, depth, flag);
	}
	default:
		return MBEDTLS_ERR_X509_FATAL_ERROR;
	}
}

int TlsConfigBase::VerifyDecentServerCert(const ServerX509Cert & cert, int depth, uint32_t & flag) const
{
	const bool verifyRes = m_state.GetServerWhiteList().AddTrustedNode(m_state, cert);
	flag = verifyRes ? MBEDTLS_SUCCESS_RET : MBEDTLS_X509_BADCERT_NOT_TRUSTED;
	return MBEDTLS_SUCCESS_RET;
}
