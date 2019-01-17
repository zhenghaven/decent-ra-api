#include "../common/DecentStates.h"

#include "../common/Decent/CertContainer.h"
#include "../common/Decent/KeyContainer.h"
#include "../common/WhiteList/DecentServer.h"
#include "../common/WhiteList/Loaded.h"
#include "../common/WhiteList/HardCoded.h"

using namespace Decent;

namespace
{
	static CertContainer certContainer;
	static KeyContainer keyContainer;
	static WhiteList::DecentServer serverWhiteList;
	static WhiteList::HardCoded hardCodedWhiteList;
}

States::States() :
	m_certContainer(certContainer),
	m_serverWhiteList(serverWhiteList),
	m_hardCodedWhiteList(hardCodedWhiteList),
	m_keyContainer(keyContainer)
{
}

const WhiteList::Loaded& States::GetLoadedWhiteList(Decent::AppX509* certPtr) const
{
	static WhiteList::Loaded inst(certPtr);
	return inst;
}
