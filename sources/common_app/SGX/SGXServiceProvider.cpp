#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL

#include "SGXServiceProvider.h"

#include "../../common/DecentStates.h"
#include "../../common/Decent/KeyContainer.h"

SGXServiceProvider::SGXServiceProvider(const std::shared_ptr<IASConnector>& ias) :
	m_ias(ias)
{
}

SGXServiceProvider::~SGXServiceProvider()
{
}

void SGXServiceProvider::GetSpPublicSignKey(general_secp256r1_public_t & outKey) const
{
	outKey = (*Decent::States::Get().GetKeyContainer().GetSignPubKey());
}

bool SGXServiceProvider::ProcessSmartMessage(const std::string & category, const Json::Value & jsonMsg, Connection& connection)
{
	return false;
}

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL
