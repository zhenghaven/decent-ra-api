#include "../../common/Decent/KeyContainer.h"

#include <memory>
#include <exception>

#include "../common/CommonTool.h"
#include "../common/MbedTlsObjects.h"

namespace
{
	static std::unique_ptr<MbedTlsObj::ECKeyPair> ConstructNewKey()
	{
		std::unique_ptr<MbedTlsObj::ECKeyPair> key = Common::make_unique<MbedTlsObj::ECKeyPair>(MbedTlsObj::gen);
		if (!key || !*key)
		{
			throw std::exception("Failed to create new key pair!"); //This should be thrown at the program startup.
		}

		return std::move(key);
	}
}


Decent::KeyContainer::KeyContainer() :
	KeyContainer(ConstructNewKey())
{
}
