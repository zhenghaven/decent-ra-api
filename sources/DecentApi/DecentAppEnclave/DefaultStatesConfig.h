#include "AppStates.h"
#include "AppStatesSingleton.h"
#include "../Common/Ra/StatesSingleton.h"

#include "AppCertContainer.h"
#include "../Common/Ra/KeyContainer.h"
#include "../Common/Ra/WhiteList/Loaded.h"
#include "../Common/Ra/WhiteList/HardCoded.h"
#include "../Common/Ra/WhiteList/DecentServer.h"

using namespace Decent::Ra;

namespace
{
	static AppCertContainer gs_certContainer;
	static KeyContainer gs_keyContainer;
	static WhiteList::DecentServer gs_serverWhiteList;
	static const WhiteList::HardCoded gs_hardCodedWhiteList;

	static const WhiteList::Loaded& GetLoadedWhiteListImpl(WhiteList::Loaded* instPtr)
	{
		static const WhiteList::Loaded inst(instPtr);
		return inst;
	}
}

AppStates& Decent::Ra::GetAppStateSingleton()
{
	static AppStates state(gs_certContainer, gs_keyContainer, gs_serverWhiteList, gs_hardCodedWhiteList, &GetLoadedWhiteListImpl);

	return state;
}

States& Decent::Ra::GetStateSingleton()
{
	return GetAppStateSingleton();
}
