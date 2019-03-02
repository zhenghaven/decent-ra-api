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
	static CertContainer gs_certContainer;
	static KeyContainer gs_keyContainer;
	static WhiteList::DecentServer gs_serverWhiteList;
	static const WhiteList::HardCoded gs_hardCodedWhiteList;

	static const WhiteList::Loaded& GetLoadedWhiteListImpl(WhiteList::Loaded* instPtr)
	{
		static const WhiteList::Loaded inst(instPtr);
		return inst;
	}
}

States& Decent::Ra::GetStateSingleton()
{
	static States state(gs_certContainer, gs_keyContainer, gs_serverWhiteList, gs_hardCodedWhiteList, &GetLoadedWhiteListImpl);

	return state;
}
