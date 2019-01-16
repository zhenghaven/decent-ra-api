#include "../common/DecentStates.h"

#include "../common/DecentCertContainer.h"
#include "../common/WhiteList/DecentServer.h"
#include "../common/WhiteList/Loaded.h"
#include "../common/WhiteList/HardCoded.h"

using namespace Decent;

namespace
{
	static CertContainer certContainer;
	static WhiteList::DecentServer serverWhiteList;
	static WhiteList::HardCoded hardCodedWhiteList;
}

States::States() :
	m_certContainer(certContainer),
	m_serverWhiteList(serverWhiteList),
	m_hardCodedWhiteList(hardCodedWhiteList)
{
}

const WhiteList::Loaded& States::GetLoadedWhiteList(Decent::AppX509* certPtr) const
{
	static WhiteList::Loaded inst(certPtr);
	return inst;
}
