#include "ClientRASession.h"

#include <sgx_tcrypto.h>

#include "../common/DataCoding.h"
#include "Networking/Connection.h"
#include "EnclaveBase.h"

ClientRASession::ClientRASession(std::unique_ptr<Connection>& connection, EnclaveBase& enclaveBase) :
	m_connection(std::move(connection)),
	m_enclaveBase(enclaveBase)
{
	sgx_ec256_public_t signPubKey;
	m_enclaveBase.GetRAClientSignPubKey(signPubKey);
	m_raSenderID = SerializePubKey(signPubKey);
}

ClientRASession::~ClientRASession()
{
}

std::string ClientRASession::GetSenderID() const
{
	return m_raSenderID;
}

void ClientRASession::SwapConnection(std::unique_ptr<Connection>& connection)
{
	m_connection.swap(connection);
}
