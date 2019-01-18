#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL

#include "ServiceProvider.h"

#include "../../common/Decent/States.h"
#include "../../common/Decent/KeyContainer.h"

Sgx::ServiceProvider::ServiceProvider(const std::shared_ptr<IASConnector>& ias) :
	m_ias(ias)
{
}

Sgx::ServiceProvider::~ServiceProvider()
{
}

void Sgx::ServiceProvider::GetSpPublicSignKey(general_secp256r1_public_t & outKey) const
{
	outKey = (*Decent::States::Get().GetKeyContainer().GetSignPubKey());
}

bool Sgx::ServiceProvider::ProcessSmartMessage(const std::string & category, const Json::Value & jsonMsg, Connection& connection)
{
	return false;
}

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL
