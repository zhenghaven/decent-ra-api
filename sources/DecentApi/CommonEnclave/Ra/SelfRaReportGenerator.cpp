#include "SelfRaReportGenerator.h"

#include "../../Common/Ra/States.h"
#include "../../Common/Ra/Crypto.h"
#include "../../Common/Ra/KeyContainer.h"
#include "../../Common/Ra/CertContainer.h"

#include "Crypto.h"

using namespace Decent::Ra;

bool SelfRaReportGenerator::GenerateAndStoreServerX509Cert(SelfRaReportGenerator & reportGenerator)
{
	using namespace Decent;

	std::string platformType;
	std::string selfRaReport;

	if (!reportGenerator.GenerateSelfRaReport(platformType, selfRaReport))
	{
		return false;
	}

	const KeyContainer& keyContainer = States::Get().GetKeyContainer();
	std::shared_ptr<const general_secp256r1_public_t> signPub = keyContainer.GetSignPubKey();
	std::shared_ptr<const MbedTlsObj::ECKeyPair> signkeyPair = keyContainer.GetSignKeyPair();

	std::shared_ptr<const ServerX509> serverCert(new ServerX509(*signkeyPair,
		Decent::Crypto::GetSelfHashBase64(), platformType, selfRaReport));
	if (!serverCert || !*serverCert)
	{
		return false;
	}
	States::Get().GetCertContainer().SetCert(serverCert);

	return true;
}
