#include "../../Common/Ra/KeyContainer.h"

#include <memory>

#include <mbedTLScpp/EcKey.hpp>

namespace
{
	static std::unique_ptr<mbedTLScpp::EcKeyPair<mbedTLScpp::EcType::SECP256R1> > ConstructNewKey()
	{
		using namespace mbedTLScpp;

		return Internal::make_unique<EcKeyPair<EcType::SECP256R1> >(
			EcKeyPair<EcType::SECP256R1>::Generate()
		);
	}
}

Decent::Ra::KeyContainer::KeyContainer() :
	KeyContainer(ConstructNewKey())
{
}
