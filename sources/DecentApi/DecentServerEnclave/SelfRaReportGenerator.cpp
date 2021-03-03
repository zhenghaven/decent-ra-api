#include "SelfRaReportGenerator.h"

#include "../Common/Ra/ServerX509Cert.h"
#include "../Common/Ra/KeyContainer.h"
#include "../Common/Tools/EnclaveId.hpp"

#include "ServerStates.h"
#include "ServerCertContainer.h"

using namespace Decent::Ra;

void SelfRaReportGenerator::GenerateAndStoreServerX509Cert(SelfRaReportGenerator & reportGenerator, ServerStates& decentStates)
{
	using namespace mbedTLScpp;

	std::string platformType;
	std::string selfRaReport;

	reportGenerator.GenerateSelfRaReport(platformType, selfRaReport);

	const KeyContainer& keyContainer = decentStates.GetKeyContainer();
	std::shared_ptr<const EcKeyPair<EcType::SECP256R1> > signKey = keyContainer.GetSignKeyPair();

	ServerX509CertWriter svrX509CertWrt(*signKey, Decent::Tools::GetSelfHashHexStr(), platformType, selfRaReport);

	std::shared_ptr<const ServerX509Cert> serverCert = std::make_shared<ServerX509Cert>(
		ServerX509Cert::FromDER(CtnFullR(svrX509CertWrt.GetDer()))
	);

	decentStates.GetServerCertContainer().SetServerCert(serverCert);
}
