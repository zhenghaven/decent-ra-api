#include "LocalAttestationSession.h"

#include <sgx_tcrypto.h>

#include "../common/DataCoding.h"
#include "Networking/Connection.h"
#include "EnclaveBase.h"

static inline std::string ConstructSenderID(EnclaveBase& enclaveBase)
{
	sgx_ec256_public_t signPubKey;
	enclaveBase.GetRAClientSignPubKey(signPubKey);
	return SerializePubKey(signPubKey);
}

LocalAttestationSession::LocalAttestationSession(std::unique_ptr<Connection>& connection, EnclaveBase & enclaveBase) :
	m_enclaveBase(enclaveBase),
	k_raSenderID(ConstructSenderID(enclaveBase))
{
	m_connection.swap(connection);
}

LocalAttestationSession::~LocalAttestationSession()
{
}

std::string LocalAttestationSession::GetSenderID() const
{
	return k_raSenderID;
}
