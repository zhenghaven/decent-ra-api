#include "ClientX509.h"

using namespace Decent::MbedTlsObj;
using namespace Decent::Ra;

ClientX509::ClientX509(const EcPublicKeyBase & pub,
	const AppX509 & verifierCert, const EcKeyPairBase & verifierPrvKey, const std::string & userName, const std::string& identity) :
	AppX509(pub, verifierCert, verifierPrvKey, userName, "DecentClient", identity, "")
{
}
