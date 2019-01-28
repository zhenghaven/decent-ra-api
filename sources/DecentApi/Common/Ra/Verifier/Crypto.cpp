#include "Crypto.h"

#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>

using namespace Decent::Ra::Verifier;

namespace
{
	static constexpr int MBEDTLS_SUCCESS_RET = 0;
}

AppX509::AppX509(const std::string & pemStr) :
	Decent::Ra::AppX509(pemStr)
{
}

AppX509::AppX509(mbedtls_x509_crt * cert) :
	Decent::Ra::AppX509(cert)
{
}

AppX509::AppX509(const Decent::Ra::AppX509 & oriCert,
	const Decent::Ra::AppX509 & verifierCert, const Decent::MbedTlsObj::ECKeyPair & verifierPrvKey,
	const std::string & appName) :
	Decent::Ra::AppX509(oriCert.GetEcPublicKey(), verifierCert, verifierPrvKey, appName, oriCert.GetPlatformType(), oriCert.GetAppId(), oriCert.GetWhiteList())
{
}
