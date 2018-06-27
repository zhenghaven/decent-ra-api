#pragma once

#include <cstdint>
#include <functional>
#include <memory>

class RAMessages;
class Connection;
class EnclaveBase;

class RemoteAttestationSession
{

public:
	RemoteAttestationSession() = delete;

	//Caution! Blocking constructors!
	RemoteAttestationSession(std::unique_ptr<Connection>& connection, EnclaveBase& enclaveBase);
	virtual ~RemoteAttestationSession();

	virtual bool ProcessClientSideRA() = 0;

	virtual bool ProcessServerSideRA() = 0;

	virtual std::string GetSenderID() const;

	std::unique_ptr<Connection>&& ReleaseConnection();

	void AssignConnection(std::unique_ptr<Connection>& inConnection);

	void SwapConnection(std::unique_ptr<Connection>& inConnection);

protected:
	std::unique_ptr<Connection> m_connection;
	EnclaveBase& m_enclaveBase;
};