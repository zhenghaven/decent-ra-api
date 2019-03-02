#include "ServerCertContainer.h"

#ifdef DECENT_THREAD_SAFETY_HIGH
#include <atomic>
#endif // DECENT_THREAD_SAFETY_HIGH

#include "../Common/Ra/Crypto.h"

using namespace Decent::Ra;

ServerCertContainer::ServerCertContainer() noexcept
{
}

ServerCertContainer::~ServerCertContainer() noexcept
{
}

std::shared_ptr<const ServerX509> ServerCertContainer::GetServerCert() const noexcept
{
#ifdef DECENT_THREAD_SAFETY_HIGH
	return std::atomic_load(&m_cert);
#else
	return m_cert;
#endif // DECENT_THREAD_SAFETY_HIGH
}

bool ServerCertContainer::SetServerCert(std::shared_ptr<const ServerX509> cert) noexcept
{
	if (!cert || !*cert || !CertContainer::SetCert(cert))
	{
		return false;
	}
#ifdef DECENT_THREAD_SAFETY_HIGH
	std::atomic_store(&m_cert, cert);
#else
	m_cert = cert;
#endif // DECENT_THREAD_SAFETY_HIGH

	return true;
}
