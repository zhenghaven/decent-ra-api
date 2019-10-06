#include "VerifiedAppX509Cert.h"

#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>

#include "../MbedTls/EcKey.h"

using namespace Decent::Ra;
using namespace Decent::MbedTlsObj;

VerifiedAppX509CertWriter::VerifiedAppX509CertWriter(AppX509Cert & oriCert, AppX509Cert & verifierCert, EcKeyPairBase & verifierPrvKey,
	const std::string & appName) :
	VerifiedAppX509CertWriter(oriCert, EcPublicKeyBase(oriCert.GetCurrPublicKey()), verifierCert, verifierPrvKey,
		appName)
{
}

Decent::Ra::VerifiedAppX509CertWriter::VerifiedAppX509CertWriter(AppX509Cert & oriCert, EcPublicKeyBase pubKey, AppX509Cert & verifierCert,
	EcKeyPairBase & verifierPrvKey, const std::string & appName) :
	AppX509CertWriter(pubKey, verifierCert, verifierPrvKey,
		appName, oriCert.GetPlatformType(), oriCert.GetAppId(), oriCert.GetWhiteList())
{
}

VerifiedAppX509CertWriter::~VerifiedAppX509CertWriter()
{
}

VerifiedAppX509Cert::VerifiedAppX509Cert(VerifiedAppX509Cert && rhs) :
	AppX509Cert(std::forward<AppX509Cert>(rhs))
{
}

VerifiedAppX509Cert::VerifiedAppX509Cert(const std::vector<uint8_t>& der) :
	AppX509Cert(der)
{
}

VerifiedAppX509Cert::VerifiedAppX509Cert(const std::string & pem) :
	AppX509Cert(pem)
{
}

VerifiedAppX509Cert::VerifiedAppX509Cert(mbedtls_x509_crt & ref) :
	AppX509Cert(ref)
{
}

VerifiedAppX509Cert & VerifiedAppX509Cert::operator=(VerifiedAppX509Cert && rhs)
{
	AppX509Cert::operator=(std::forward<AppX509Cert>(rhs));
	return *this;
}
