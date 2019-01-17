#include "../common/Decent/States.h"

#include "../common/Decent/KeyContainer.h"
#include "../common/Decent/CertContainer.h"
#include "../common/Decent/WhiteList/Loaded.h"
#include "../common/Decent/WhiteList/HardCoded.h"
#include "../common/Decent/WhiteList/DecentServer.h"

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
