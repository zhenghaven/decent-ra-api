#include "SelfRaReportGenerator.h"

#include "../Common/Ra/Crypto.h"
#include "../Common/Ra/KeyContainer.h"

#include "../CommonEnclave/Ra/Crypto.h"

#include "ServerStates.h"
#include "ServerCertContainer.h"

using namespace Decent::Ra;

bool SelfRaReportGenerator::GenerateAndStoreServerX509Cert(SelfRaReportGenerator & reportGenerator, ServerStates& decentStates)
{
	using namespace Decent;

	std::string platformType;
	std::string selfRaReport;

	if (!reportGenerator.GenerateSelfRaReport(platformType, selfRaReport))
	{
		return false;
	}

	const KeyContainer& keyContainer = decentStates.GetKeyContainer();
	std::shared_ptr<const MbedTlsObj::ECKeyPair> signkeyPair = keyContainer.GetSignKeyPair();

	std::shared_ptr<const ServerX509> serverCert(new ServerX509(*signkeyPair,
		Decent::Crypto::GetSelfHashBase64(), platformType, selfRaReport));

	return decentStates.GetServerCertContainer().SetServerCert(serverCert);
}
