#include "DecentCertContainer.h"

#include "GeneralKeyTypes.h"
#include "DecentCrypto.h"

DecentCertContainer & DecentCertContainer::Get()
{
	static DecentCertContainer inst;
	return inst;
}

bool DecentCertContainer::SetServerCert(std::shared_ptr<const Decent::ServerX509> serverCert)
{
	if (!serverCert || !*serverCert)
	{
		return false;
	}

	std::shared_ptr<general_secp256r1_public_t> serverKeyGeneral(new general_secp256r1_public_t);
	if (!serverKeyGeneral || 
		!serverCert->GetEcPublicKey().ToGeneralPublicKey(*serverKeyGeneral))
	{
		return false;
	}

#ifdef DECENT_THREAD_SAFETY_HIGH
	std::atomic_store(&m_serverCert, serverCert);
	std::atomic_store(&m_serverKeyGeneral, serverKeyGeneral);
#else
	m_serverCert = serverCert;
	m_serverKeyGeneral = serverKeyGeneral;
#endif // DECENT_THREAD_SAFETY_HIGH

	return true;
}
