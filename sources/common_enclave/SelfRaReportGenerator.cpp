#include "SelfRaReportGenerator.h"

#include "DecentCrypto.h"
#include "../common/DecentCrypto.h"
#include "../common/CryptoKeyContainer.h"
#include "../common/DecentCertContainer.h"

bool SelfRaReportGenerator::GenerateAndStoreServerX509Cert(SelfRaReportGenerator & reportGenerator)
{
	std::string platformType;
	std::string selfRaReport;

	if (!reportGenerator.GenerateSelfRaReport(platformType, selfRaReport))
	{
		return false;
	}

	std::shared_ptr<const general_secp256r1_public_t> signPub = CryptoKeyContainer::GetInstance().GetSignPubKey();
	std::shared_ptr<const MbedTlsObj::ECKeyPair> signkeyPair = CryptoKeyContainer::GetInstance().GetSignKeyPair();

	std::shared_ptr<const Decent::ServerX509> serverCert(new Decent::ServerX509(*signkeyPair,
		Decent::Crypto::GetProgSelfHashBase64(), platformType, selfRaReport));
	if (!serverCert || !*serverCert)
	{
		return false;
	}
	DecentCertContainer::Get().SetServerCert(serverCert);

	std::shared_ptr<const Decent::AppX509> dummyAppCert(new Decent::AppX509(*signkeyPair, *serverCert, *signkeyPair,
		Decent::Crypto::GetProgSelfHashBase64(), platformType, ""));
	DecentCertContainer::Get().SetCert(dummyAppCert);

	Decent::Crypto::RefreshDecentAppAppClientSideConfig();
	Decent::Crypto::RefreshDecentAppAppServerSideConfig();
	Decent::Crypto::RefreshDecentAppClientServerSideConfig();

	return true;
}
