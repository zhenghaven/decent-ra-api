#include "SelfRaReportGenerator.h"

#include "../Common/MbedTls/Drbg.h"
#include "../Common/MbedTls/EcKey.h"

#include "../Common/Ra/ServerX509Cert.h"
#include "../Common/Ra/KeyContainer.h"

#include "../CommonEnclave/Tools/Crypto.h"

#include "ServerStates.h"
#include "ServerCertContainer.h"

using namespace Decent::Ra;
using namespace Decent::MbedTlsObj;

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
	EcKeyPair<EcKeyType::SECP256R1> signKey = *keyContainer.GetSignKeyPair();

	ServerX509CertWriter svrX509CertWrt(signKey, Decent::Tools::GetSelfHashBase64(), platformType, selfRaReport);

	Drbg drbg;
	std::shared_ptr<const ServerX509Cert> serverCert = std::make_shared<ServerX509Cert>(svrX509CertWrt.GenerateDer(drbg));

	return decentStates.GetServerCertContainer().SetServerCert(serverCert);
}
