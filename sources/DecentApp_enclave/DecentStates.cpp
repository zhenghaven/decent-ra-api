#include "../common/DecentStates.h"

#include "../common/DecentCertContainer.h"

using namespace Decent;

namespace
{
	static CertContainer certContainer;
}

States::States() :
	m_certContainer(certContainer)
{
}
