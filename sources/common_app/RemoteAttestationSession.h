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
	//typedef std::function<RAMessages*(const RAMessages&)> MsgProcessor;

	//enum Mode
	//{
	//	Server,
	//	Client,
	//};

public:
	RemoteAttestationSession() = delete;

	//Caution! Blocking constructors!
	RemoteAttestationSession(std::unique_ptr<Connection>& connection);
	virtual ~RemoteAttestationSession();

	virtual bool ProcessClientSideRA(EnclaveBase& enclave) = 0;

	virtual bool ProcessServerSideRA(EnclaveBase& enclave) = 0;

	std::unique_ptr<Connection>&& ReleaseConnection();

	void AssignConnection(std::unique_ptr<Connection>& inConnection);

	void SwapConnection(std::unique_ptr<Connection>& inConnection);

protected:
	//Mode GetMode() const;

	std::unique_ptr<Connection> m_connection;
	//Mode m_mode;
};