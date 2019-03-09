#include "States.h"
#include "StatesSingleton.h"

#include "KeyContainer.h"
#include "CertContainer.h"
#include "WhiteList/Loaded.h"
#include "WhiteList/HardCoded.h"
#include "WhiteList/DecentServer.h"

using namespace Decent::Ra;

namespace
{
	static CertContainer& GetCertContainer()
	{
		static CertContainer inst;
		return inst;
	}

	static KeyContainer& GetKeyContainer()
	{
		static KeyContainer inst;
		return inst;
	}

	static WhiteList::DecentServer& GetServerWhiteList()
	{
		static WhiteList::DecentServer inst;
		return inst;
	}

	static const WhiteList::HardCoded& GetHardCodedWhiteList()
	{
		static const WhiteList::HardCoded inst;
		return inst;
	}

	static const WhiteList::Loaded& GetLoadedWhiteListImpl(WhiteList::Loaded* instPtr)
	{
		static const WhiteList::Loaded inst(instPtr);
		return inst;
	}
}

States& Decent::Ra::GetStateSingleton()
{
	static States state(GetCertContainer(), GetKeyContainer(), GetServerWhiteList(), GetHardCodedWhiteList(), &GetLoadedWhiteListImpl);

	return state;
}
