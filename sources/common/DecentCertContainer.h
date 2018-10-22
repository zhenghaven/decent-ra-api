#pragma once

#include <memory>
#ifdef DECENT_THREAD_SAFETY_HIGH
#include <atomic>
#endif // DECENT_THREAD_SAFETY_HIGH

namespace Decent
{
	class AppX509;
	class ServerX509;
}

typedef struct _general_secp256r1_public_t general_secp256r1_public_t;

#ifdef DECENT_THREAD_SAFETY_HIGH
#include <atomic>
#endif // DECENT_THREAD_SAFETY_HIGH

class DecentCertContainer
{
public:
	static DecentCertContainer& Get();

	~DecentCertContainer() {}

	std::shared_ptr<const Decent::AppX509> GetCert() const
	{
#ifdef DECENT_THREAD_SAFETY_HIGH
		return std::atomic_load(&m_cert);
#else
		return m_cert;
#endif // DECENT_THREAD_SAFETY_HIGH
	}

	std::shared_ptr<const Decent::ServerX509> GetServerCert() const
	{
#ifdef DECENT_THREAD_SAFETY_HIGH
		return std::atomic_load(&m_serverCert);
#else
		return m_serverCert;
#endif // DECENT_THREAD_SAFETY_HIGH
	}

	std::shared_ptr<const general_secp256r1_public_t> GetServerKeyGeneral() const
	{
#ifdef DECENT_THREAD_SAFETY_HIGH
		return std::atomic_load(&m_serverKeyGeneral);
#else
		return m_serverKeyGeneral;
#endif // DECENT_THREAD_SAFETY_HIGH
	}

	void SetCert(std::shared_ptr<const Decent::AppX509> cert)
	{
#ifdef DECENT_THREAD_SAFETY_HIGH
		std::atomic_store(&m_cert, cert);
#else
		m_cert = cert;
#endif // DECENT_THREAD_SAFETY_HIGH
	}

	bool SetServerCert(std::shared_ptr<const Decent::ServerX509> serverCert);

private:
	DecentCertContainer() {}

	std::shared_ptr<const Decent::AppX509> m_cert;
	std::shared_ptr<const Decent::ServerX509> m_serverCert;
	std::shared_ptr<const general_secp256r1_public_t> m_serverKeyGeneral;
};
