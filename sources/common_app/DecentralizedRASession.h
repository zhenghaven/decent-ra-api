#pragma once

#include <memory>
#include <string>

class DecentralizedEnclave;
class Connection;
class EnclaveBase;
class ServiceProviderBase;
class ClientRASession;
class ServiceProviderRASession;

typedef struct _spid_t sgx_spid_t;

class DecentralizedRASession
{
public:
	DecentralizedRASession() = delete;
	DecentralizedRASession(std::unique_ptr<Connection>& connection, EnclaveBase& hardwareEnclave, ServiceProviderBase& sp, DecentralizedEnclave& enclave);
	
	virtual ~DecentralizedRASession();

	virtual bool ProcessClientSideRA();

	virtual bool ProcessServerSideRA();

	void AssignConnection(std::unique_ptr<Connection>& inConnection);

	void SwapConnection(std::unique_ptr<Connection>& inConnection);

protected:
	std::unique_ptr<Connection> m_connection;
	EnclaveBase& m_hardwareEnclave;
	ServiceProviderBase& m_sp;
	std::shared_ptr<ClientRASession> m_hardwareSession;
	std::shared_ptr<ServiceProviderRASession> m_spSession;

	virtual bool SendReverseRARequest(const std::string& senderID);

	virtual bool RecvReverseRARequest();

private:
	DecentralizedEnclave& m_decentralizedEnc;
	bool m_isEnclaveEnvInited;
};
