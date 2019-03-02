#include "ServerStates.h"
#include "ServerStatesSingleton.h"
#include "../Common/Ra/StatesSingleton.h"

#include "ServerCertContainer.h"
#include "../Common/Ra/KeyContainer.h"
#include "../Common/Ra/WhiteList/Loaded.h"
#include "../Common/Ra/WhiteList/HardCoded.h"
#include "../Common/Ra/WhiteList/DecentServer.h"

using namespace Decent::Ra;

namespace
{
	static ServerCertContainer gs_certContainer;
	static KeyContainer gs_keyContainer;
	static WhiteList::DecentServer gs_serverWhiteList;
	static const WhiteList::HardCoded gs_hardCodedWhiteList;

	static const WhiteList::Loaded& GetLoadedWhiteListImpl(WhiteList::Loaded* instPtr)
	{
		static const WhiteList::Loaded inst(instPtr);
		return inst;
	}
}

ServerStates& Decent::Ra::GetServerStateSingleton()
{
	static ServerStates state(gs_certContainer, gs_keyContainer, gs_serverWhiteList, gs_hardCodedWhiteList, &GetLoadedWhiteListImpl);

	return state;
}

States& Decent::Ra::GetStateSingleton()
{
	return GetServerStateSingleton();
}
