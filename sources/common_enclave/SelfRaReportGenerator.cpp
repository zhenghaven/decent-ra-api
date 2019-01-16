#include "SelfRaReportGenerator.h"

#include "DecentCrypto.h"
#include "../common/DecentStates.h"
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
	Decent::States::Get().GetCertContainer().SetCert(serverCert);

	//TODO: We probably don't need these:
	//Decent::Crypto::RefreshDecentAppAppClientSideConfig();
	//Decent::Crypto::RefreshDecentAppAppServerSideConfig();
	//Decent::Crypto::RefreshDecentAppClientServerSideConfig();

	return true;
}
