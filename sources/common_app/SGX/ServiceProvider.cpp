#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL

#include "ServiceProvider.h"

#include "../../common/Ra/States.h"
#include "../../common/Ra/KeyContainer.h"

using namespace Decent::Sgx;
using namespace Decent::Ias;

ServiceProvider::ServiceProvider(const std::shared_ptr<Connector>& ias) :
	m_ias(ias)
{
}

ServiceProvider::~ServiceProvider()
{
}

void ServiceProvider::GetSpPublicSignKey(general_secp256r1_public_t & outKey) const
{
	outKey = (*Decent::Ra::States::Get().GetKeyContainer().GetSignPubKey());
}

bool ServiceProvider::ProcessSmartMessage(const std::string & category, const Json::Value & jsonMsg, Decent::Net::Connection& connection)
{
	return false;
}

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL
