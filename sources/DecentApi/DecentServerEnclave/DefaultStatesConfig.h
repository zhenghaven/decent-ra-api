#include "ServerStates.h"
#include "ServerStatesSingleton.h"
#include "../Common/Ra/StatesSingleton.h"

#include "ServerCertContainer.h"
#include "AppWhiteListsManager.h"
#include "../Common/Ra/KeyContainer.h"
#include "../Common/Ra/WhiteList/LoadedList.h"
#include "../Common/Ra/WhiteList/DecentServer.h"

using namespace Decent::Ra;

namespace
{
	static ServerCertContainer& GetCertContainer()
	{
		static ServerCertContainer inst;
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

	static WhiteList::AppWhiteListsManager& GetAppWhiteListMgr()
	{
		static WhiteList::AppWhiteListsManager inst;
		return inst;
	}

	static const WhiteList::LoadedList& GetLoadedWhiteListImpl(WhiteList::LoadedList* instPtr)
	{
		static const WhiteList::LoadedList inst(instPtr);
		return inst;
	}
}

ServerStates& Decent::Ra::GetServerStateSingleton()
{
	static ServerStates state(GetCertContainer(), GetKeyContainer(), GetServerWhiteList(), GetAppWhiteListMgr(), &GetLoadedWhiteListImpl);

	return state;
}

States& Decent::Ra::GetStateSingleton()
{
	return GetServerStateSingleton();
}
