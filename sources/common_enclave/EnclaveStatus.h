#pragma once

#include <map>

#include "../common_enclave/RAConnection.h"
#include "../common_enclave/RAKeyManager.h"
#include "../common_enclave/DecentCryptoManager.h"

class EnclaveState
{
public:
	static EnclaveState& GetInstance();

	EnclaveState();
	~EnclaveState();

	void Clear();

	//SGX RA Client:
	std::map<std::string, std::pair<ServerRAState, RAKeyManager> >& GetServersMap();

	//SGX RA Service Provider:
	std::map<std::string, std::pair<ClientRAState, RAKeyManager> >& GetClientsMap();

	//SGX Decent:
	DecentCryptoManager& GetCryptoMgr();

private:

	//SGX RA Client:
	std::map<std::string, std::pair<ServerRAState, RAKeyManager> > m_serversMap;

	//SGX RA Service Provider:
	std::map<std::string, std::pair<ClientRAState, RAKeyManager> > m_clientsMap;

	//SGX Decent:
	DecentCryptoManager m_cryptoMgr;

};

