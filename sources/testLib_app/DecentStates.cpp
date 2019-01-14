#include "../common/DecentStates.h"

#include "../common/DecentCertContainer.h"
#include "../common/WhiteList/DecentServer.h"

using namespace Decent;

namespace
{
	static CertContainer certContainer;
	static WhiteList::DecentServer serverWhiteList;
}

States::States() :
	m_certContainer(certContainer),
	m_serverWhiteList(serverWhiteList)
{
}
