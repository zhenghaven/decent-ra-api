#pragma once

#include <memory>

#include "../common/DecentCrypto.h"

#ifdef DECENT_THREAD_SAFETY_HIGH
#include <atomic>
#endif // DECENT_THREAD_SAFETY_HIGH

class DecentCertContainer
{
public:
	static DecentCertContainer& Get()
	{
		static DecentCertContainer inst;
		return inst;
	}

	~DecentCertContainer() {}

	std::shared_ptr<const MbedTlsObj::X509Cert> GetCert() const
	{
#ifdef DECENT_THREAD_SAFETY_HIGH
		return std::atomic_load(&m_cert);
#else
		return m_cert;
#endif // DECENT_THREAD_SAFETY_HIGH
	}

	std::shared_ptr<const MbedTlsDecentServerX509> GetServerCert() const
	{
#ifdef DECENT_THREAD_SAFETY_HIGH
		return std::atomic_load(&m_serverCert);
#else
		return m_serverCert;
#endif // DECENT_THREAD_SAFETY_HIGH
	}

	void SetCert(std::shared_ptr<const MbedTlsObj::X509Cert> cert)
	{
#ifdef DECENT_THREAD_SAFETY_HIGH
		std::atomic_store(&m_cert, cert);
#else
		m_cert = cert;
#endif // DECENT_THREAD_SAFETY_HIGH
	}

	void SetServerCert(std::shared_ptr<const MbedTlsDecentServerX509> serverCert)
	{
#ifdef DECENT_THREAD_SAFETY_HIGH
		std::atomic_store(&m_serverCert, serverCert);
#else
		m_serverCert = serverCert;
#endif // DECENT_THREAD_SAFETY_HIGH
	}

private:
	DecentCertContainer() {}

	std::shared_ptr<const MbedTlsObj::X509Cert> m_cert;
	std::shared_ptr<const MbedTlsDecentServerX509> m_serverCert;
};
