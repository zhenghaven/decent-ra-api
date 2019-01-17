#include "SelfRaReportGenerator.h"

#include "../common/Decent/States.h"
#include "../common/Decent/Crypto.h"
#include "../common/Decent/KeyContainer.h"
#include "../common/Decent/CertContainer.h"

#include "../common_enclave/DecentCrypto.h"

bool SelfRaReportGenerator::GenerateAndStoreServerX509Cert(SelfRaReportGenerator & reportGenerator)
{
	using namespace Decent;

	std::string platformType;
	std::string selfRaReport;

	if (!reportGenerator.GenerateSelfRaReport(platformType, selfRaReport))
	{
		return false;
	}

	const KeyContainer& keyContainer = Decent::States::Get().GetKeyContainer();
	std::shared_ptr<const general_secp256r1_public_t> signPub = keyContainer.GetSignPubKey();
	std::shared_ptr<const MbedTlsObj::ECKeyPair> signkeyPair = keyContainer.GetSignKeyPair();

	std::shared_ptr<const Decent::ServerX509> serverCert(new Decent::ServerX509(*signkeyPair,
		Decent::Crypto::GetSelfHashBase64(), platformType, selfRaReport));
	if (!serverCert || !*serverCert)
	{
		return false;
	}
	Decent::States::Get().GetCertContainer().SetCert(serverCert);

	return true;
}
