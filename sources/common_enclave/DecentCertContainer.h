#pragma once

#include <memory>

#include "../common/OpenSSLTools.h"

#ifdef DECENT_THREAD_SAFETY_HIGH
#include <atomic>
#endif // DECENT_THREAD_SAFETY_HIGH

class X509Wrapper;

class DecentCertContainer
{
public:
	static DecentCertContainer& Get()
	{
		static DecentCertContainer inst;
		return inst;
	}

	~DecentCertContainer() {}

	std::shared_ptr<const X509Wrapper> GetCert() const
	{
#ifdef DECENT_THREAD_SAFETY_HIGH
		return std::atomic_load(&m_cert);
#else
		return m_cert;
#endif // DECENT_THREAD_SAFETY_HIGH
	}

	std::shared_ptr<const DecentServerX509> GetServerCert() const
	{
#ifdef DECENT_THREAD_SAFETY_HIGH
		return std::atomic_load(&m_serverCert);
#else
		return m_serverCert;
#endif // DECENT_THREAD_SAFETY_HIGH
	}

	void SetCert(std::shared_ptr<const X509Wrapper> cert)
	{
#ifdef DECENT_THREAD_SAFETY_HIGH
		std::atomic_store(&m_cert, cert);
#else
		m_cert = cert;
#endif // DECENT_THREAD_SAFETY_HIGH
	}

	void SetServerCert(std::shared_ptr<const DecentServerX509> serverCert)
	{
#ifdef DECENT_THREAD_SAFETY_HIGH
		std::atomic_store(&m_serverCert, serverCert);
#else
		m_serverCert = serverCert;
#endif // DECENT_THREAD_SAFETY_HIGH
	}

private:
	DecentCertContainer() {}

	std::shared_ptr<const X509Wrapper> m_cert;
	std::shared_ptr<const DecentServerX509> m_serverCert;
};
