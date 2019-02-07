#include "States.h"

#include "KeyContainer.h"
#include "CertContainer.h"
#include "WhiteList/Loaded.h"
#include "WhiteList/HardCoded.h"
#include "WhiteList/DecentServer.h"

using namespace Decent::Ra;

namespace
{
	static CertContainer certContainer;
	static KeyContainer keyContainer;
	static WhiteList::DecentServer serverWhiteList;
	static WhiteList::HardCoded hardCodedWhiteList;

	static const WhiteList::Loaded& GetLoadedWhiteListImpl(AppX509* certPtr)
	{
		static WhiteList::Loaded inst(certPtr);
		return inst;
	}
}

States::States() :
	m_certContainer(certContainer),
	m_serverWhiteList(serverWhiteList),
	m_hardCodedWhiteList(hardCodedWhiteList),
	m_keyContainer(keyContainer),
	m_getLoadedFunc(&GetLoadedWhiteListImpl)
{
}
