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
	auto keyPair = gs_states.GetKeyContainer().GetSignKeyPair();

	std::array<uint8_t, 32> x, y;
	std::tie(x, y, std::ignore) = keyPair->GetPublicBytes();

	std::copy(x.begin(), x.end(), std::begin(outKey.x));
	std::copy(y.begin(), y.end(), std::begin(outKey.y));
}

bool ServiceProvider::ProcessSmartMessage(const std::string & category, ConnectionBase& connection, ConnectionBase*& freeHeldCnt)
{
	return false;
}
