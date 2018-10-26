#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL

#include "SGXServiceProvider.h"

#include "../../common/CryptoKeyContainer.h"

SGXServiceProvider::SGXServiceProvider(const std::shared_ptr<IASConnector>& ias) :
	m_ias(ias)
{
}

SGXServiceProvider::~SGXServiceProvider()
{
}

void SGXServiceProvider::GetSpPublicSignKey(general_secp256r1_public_t & outKey) const
{
	outKey = (*CryptoKeyContainer::GetInstance().GetSignPubKey());
}

bool SGXServiceProvider::ProcessSmartMessage(const std::string & category, const Json::Value & jsonMsg, Connection& connection)
{
	return false;
}

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL
