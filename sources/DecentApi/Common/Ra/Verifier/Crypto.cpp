#include "Crypto.h"

#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>

using namespace Decent::Ra::Verifier;

AppX509::AppX509(const Decent::Ra::AppX509 & oriCert,
	const Decent::Ra::AppX509 & verifierCert, const Decent::MbedTlsObj::EcKeyPairBase & verifierPrvKey,
	const std::string & appName) :
	Decent::Ra::AppX509(oriCert.GetEcPublicKey(), verifierCert, verifierPrvKey, appName, oriCert.GetPlatformType(), oriCert.GetAppId(), oriCert.GetWhiteList())
{
}
