#include "../../Common/Ra/KeyContainer.h"

#include <memory>
#include <exception>

#include "../../Common/Common.h"
#include "../../Common/make_unique.h"
#include "../../Common/MbedTls/MbedTlsObjects.h"

using namespace Decent;
using namespace Decent::Ra;

namespace
{
	static std::unique_ptr<MbedTlsObj::ECKeyPair> ConstructNewKey()
	{
		std::unique_ptr<MbedTlsObj::ECKeyPair> key = Tools::make_unique<MbedTlsObj::ECKeyPair>(MbedTlsObj::ECKeyPair::GenerateNewKey());
		if (!key || !*key)
		{
			LOGW("Failed to create new key pair!");
			throw std::runtime_error("Failed to create new key pair!"); //If error happened, this should be thrown at the program startup.
		}

		return std::move(key);
	}
}

KeyContainer::KeyContainer() :
	KeyContainer(ConstructNewKey())
{
}
