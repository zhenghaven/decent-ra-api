#include "CertContainer.h"

#ifdef DECENT_THREAD_SAFETY_HIGH
#include <atomic>
#endif // DECENT_THREAD_SAFETY_HIGH

#include "../MbedTls/X509Cert.h"
#include "../Common.h"

using namespace Decent::Ra;
using namespace Decent::MbedTlsObj;

CertContainer::CertContainer() noexcept
{
}

CertContainer::~CertContainer() noexcept
{
}

std::shared_ptr<const X509Cert> CertContainer::GetCert() const noexcept
{
#ifdef DECENT_THREAD_SAFETY_HIGH
	return std::atomic_load(&m_cert);
#else
	return m_cert;
#endif // DECENT_THREAD_SAFETY_HIGH
}

bool CertContainer::SetCert(std::shared_ptr<const X509Cert> cert) noexcept
{
	if (!cert)
	{
		return false;
	}
#ifdef DECENT_THREAD_SAFETY_HIGH
	std::atomic_store(&m_cert, cert);
#else
	m_cert = cert;
#endif // DECENT_THREAD_SAFETY_HIGH

	LOGI("Saved Cert: \n %s \n", cert->GetPemChain().c_str());

	return true;
}
