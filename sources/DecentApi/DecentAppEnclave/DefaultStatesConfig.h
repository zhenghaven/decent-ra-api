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
	static AppCertContainer& GetCertContainer()
	{
		static AppCertContainer inst;
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

AppStates& Decent::Ra::GetAppStateSingleton()
{
	static AppStates state(GetCertContainer(), GetKeyContainer(), GetServerWhiteList(), GetHardCodedWhiteList(), &GetLoadedWhiteListImpl);

	return state;
}

States& Decent::Ra::GetStateSingleton()
{
	return GetAppStateSingleton();
}
