#include "CertContainer.h"

#ifdef DECENT_THREAD_SAFETY_HIGH
#include <atomic>
#endif // DECENT_THREAD_SAFETY_HIGH

#include "../MbedTls/MbedTlsObjects.h"
#include "../Common.h"

using namespace Decent::Ra;

CertContainer::CertContainer() noexcept
{
}

CertContainer::~CertContainer() noexcept
{
}

std::shared_ptr<const Decent::MbedTlsObj::X509Cert> CertContainer::GetCert() const noexcept
{
#ifdef DECENT_THREAD_SAFETY_HIGH
	return std::atomic_load(&m_cert);
#else
	return m_cert;
#endif // DECENT_THREAD_SAFETY_HIGH
}

bool CertContainer::SetCert(std::shared_ptr<const Decent::MbedTlsObj::X509Cert> cert) noexcept
{
	if (!cert || !*cert)
	{
		return false;
	}
#ifdef DECENT_THREAD_SAFETY_HIGH
	std::atomic_store(&m_cert, cert);
#else
	m_cert = cert;
#endif // DECENT_THREAD_SAFETY_HIGH

	LOGI("Saved Cert: \n %s \n", cert->ToPemString().c_str());

	return true;
}
