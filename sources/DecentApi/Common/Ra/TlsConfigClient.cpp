#include "TlsConfigClient.h"

#include <mbedtls/ssl.h>

#include "ClientX509.h"

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
		ClientX509 certObj(cert);
		if (!certObj)
		{
			flag = MBEDTLS_X509_BADCERT_NOT_TRUSTED;
			return MBEDTLS_SUCCESS_RET;
		}

		return VerifyClientCert(certObj, depth, flag);
	}
	case 1: //Decent App Cert
	{
		AppX509 certObj(cert);
		if (!certObj)
		{
			flag = MBEDTLS_X509_BADCERT_NOT_TRUSTED;
			return MBEDTLS_SUCCESS_RET;
		}

		return VerifyDecentAppCert(certObj, depth, flag);
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

int TlsConfigClient::VerifyClientCert(const ClientX509 & cert, int depth, uint32_t & flag) const
{
	//Currently we don't verify anything as long as the client's cert is signed by the expected Decent App.
	return MBEDTLS_SUCCESS_RET;
}
