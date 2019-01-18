#include "../../common/Ra/KeyContainer.h"

#include <memory>
#include <exception>

#include "../common/CommonTool.h"
#include "../common/MbedTls/MbedTlsObjects.h"

using namespace Decent;
using namespace Decent::Ra;

namespace
{
	static std::unique_ptr<MbedTlsObj::ECKeyPair> ConstructNewKey()
	{
		std::unique_ptr<MbedTlsObj::ECKeyPair> key = Common::make_unique<MbedTlsObj::ECKeyPair>(MbedTlsObj::gen);
		if (!key || !*key)
		{
			LOGW("Failed to create new key pair!");
			throw std::exception("Failed to create new key pair!"); //This should be thrown at the program startup.
		}

		return std::move(key);
	}
}

KeyContainer::KeyContainer() :
	KeyContainer(ConstructNewKey())
{
}
