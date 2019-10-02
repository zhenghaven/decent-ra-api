#include "../../Common/Ra/KeyContainer.h"

#include <memory>
#include <exception>

#include "../../Common/Common.h"
#include "../../Common/make_unique.h"
#include "../../Common/MbedTls/EcKey.h"
#include "../../Common/MbedTls/Drbg.h"

using namespace Decent::Ra;
using namespace Decent::Tools;
using namespace Decent::MbedTlsObj;

namespace
{
	static std::unique_ptr<EcKeyPair<EcKeyType::SECP256R1> > ConstructNewKey()
	{
		return make_unique<EcKeyPair<EcKeyType::SECP256R1> >(EcKeyPair<EcKeyType::SECP256R1>(make_unique<Drbg>()));
	}
}

KeyContainer::KeyContainer() :
	KeyContainer(ConstructNewKey())
{
}
