#include "ServiceProvider.h"

#include "../../Common/Ra/StatesSingleton.h"
#include "../../Common/Ra/KeyContainer.h"

using namespace Decent::Sgx;
using namespace Decent::Ias;
using namespace Decent::Net;

namespace
{
	static Decent::Ra::States& gs_states = Decent::Ra::GetStateSingleton();
}

ServiceProvider::ServiceProvider(const std::shared_ptr<Connector>& ias) :
	m_ias(ias)
{
}

ServiceProvider::~ServiceProvider()
{
}

void ServiceProvider::GetSpPublicSignKey(general_secp256r1_public_t & outKey) const
{
	outKey = (*gs_states.GetKeyContainer().GetSignPubKey());
}

bool ServiceProvider::ProcessSmartMessage(const std::string & category, ConnectionBase& connection, ConnectionBase*& freeHeldCnt)
{
	return false;
}
