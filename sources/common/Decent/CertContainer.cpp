#include "CertContainer.h"

#ifdef DECENT_THREAD_SAFETY_HIGH
#include <atomic>
#endif // DECENT_THREAD_SAFETY_HIGH

#include "../DecentCrypto.h"
#include "../CommonTool.h"

Decent::CertContainer::CertContainer()
{
}

Decent::CertContainer::~CertContainer()
{
}

std::shared_ptr<const MbedTlsObj::X509Cert> Decent::CertContainer::GetCert() const
{
#ifdef DECENT_THREAD_SAFETY_HIGH
	return std::atomic_load(&m_cert);
#else
	return m_cert;
#endif // DECENT_THREAD_SAFETY_HIGH
}

bool Decent::CertContainer::SetCert(std::shared_ptr<const MbedTlsObj::X509Cert> cert)
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

	COMMON_PRINTF("Saved Cert: \n %s \n", cert->ToPemString().c_str());

	return true;
}
