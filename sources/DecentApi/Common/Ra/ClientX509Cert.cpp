#include "ClientX509Cert.h"

using namespace Decent::Ra;
using namespace Decent::MbedTlsObj;

ClientX509CertWriter::ClientX509CertWriter(EcPublicKeyBase & pubKey, const AppX509Cert & appCert, EcKeyPairBase & appPrvKey,
	const std::string & userName, const std::string & identity) :
	AppX509CertWriter(pubKey, appCert, appPrvKey, userName, "DecentClient", identity, "{}")
{
}

ClientX509CertWriter::~ClientX509CertWriter()
{
}

ClientX509Cert::ClientX509Cert(ClientX509Cert && rhs) :
	AppX509Cert(std::forward<AppX509Cert>(rhs))
{}

ClientX509Cert::ClientX509Cert(const std::vector<uint8_t>& der) :
	AppX509Cert(der)
{
}

ClientX509Cert::ClientX509Cert(const std::string & pem) :
	AppX509Cert(pem)
{
}

ClientX509Cert::ClientX509Cert(mbedtls_x509_crt & ref) :
	AppX509Cert(ref)
{}

ClientX509Cert::~ClientX509Cert()
{
}

ClientX509Cert & ClientX509Cert::operator=(ClientX509Cert && rhs)
{
	AppX509Cert::operator=(std::forward<AppX509Cert>(rhs));
	return *this;
}
