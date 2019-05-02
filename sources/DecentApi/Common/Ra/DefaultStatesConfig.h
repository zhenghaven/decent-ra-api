#include "States.h"
#include "StatesSingleton.h"

#include "KeyContainer.h"
#include "CertContainer.h"
#include "WhiteList/LoadedList.h"
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

	static const WhiteList::LoadedList& GetLoadedWhiteListImpl(WhiteList::LoadedList* instPtr)
	{
		static const WhiteList::LoadedList inst(instPtr);
		return inst;
	}
}

States& Decent::Ra::GetStateSingleton()
{
	static States state(GetCertContainer(), GetKeyContainer(), GetServerWhiteList(), &GetLoadedWhiteListImpl);

	return state;
}
