#include "ClientRASession.h"

#include <sgx_tcrypto.h>

#include "../common/DataCoding.h"
#include "Networking/Connection.h"
#include "EnclaveBase.h"

static std::string ConstructSenderID(EnclaveBase& enclaveBase)
{
	sgx_ec256_public_t signPubKey;
	enclaveBase.GetRAClientSignPubKey(signPubKey);
	return SerializePubKey(signPubKey);
}

ClientRASession::ClientRASession(std::unique_ptr<Connection>& connection, EnclaveBase& enclaveBase) :
	m_enclaveBase(enclaveBase),
	k_raSenderID(ConstructSenderID(enclaveBase))
{
	m_connection.swap(connection);
}

ClientRASession::~ClientRASession()
{
}

std::string ClientRASession::GetSenderID() const
{
	return k_raSenderID;
}
