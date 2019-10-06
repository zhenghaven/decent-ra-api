#include "TlsConfigClient.h"

#include <mbedtls/ssl.h>

#include "ClientX509Cert.h"
#include "ServerX509Cert.h"

using namespace Decent::Ra;
using namespace Decent::MbedTlsObj;

TlsConfigClient::TlsConfigClient(Decent::Ra::States & state, Mode cntMode, const std::string & expectedRegisterName, std::shared_ptr<SessionTicketMgrBase> ticketMgr) :
	TlsConfigWithName(state, cntMode, expectedRegisterName, ticketMgr)
{
}

TlsConfigClient::~TlsConfigClient()
{
}

int TlsConfigClient::VerifyCert(mbedtls_x509_crt & cert, int depth, uint32_t & flag) const
{
	switch (depth)
	{
	case 0: //Client Cert
	{
		ClientX509Cert certObj(cert);

		return VerifyClientCert(certObj, depth, flag);
	}
	case 1: //Decent App Cert
	{
		AppX509Cert certObj(cert);

		return VerifyDecentAppCert(certObj, depth, flag);
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

int TlsConfigClient::VerifyClientCert(const ClientX509Cert & cert, int depth, uint32_t & flag) const
{
	//Currently we don't verify anything as long as the client's cert is signed by the expected Decent App.
	return MBEDTLS_SUCCESS_RET;
}
