#include "EnclaveStatus.h"



EnclaveState & EnclaveState::GetInstance()
{
	static EnclaveState inst;
	return inst;
}

EnclaveState::EnclaveState()
{
}


EnclaveState::~EnclaveState()
{
}

void EnclaveState::Clear()
{
	m_clientsMap.clear();
	m_serversMap.clear();
	//m_cryptoMgr.clear();
}

std::map<std::string, std::pair<ServerRAState, RAKeyManager>>& EnclaveState::GetServersMap()
{
	return m_serversMap;
}

std::map<std::string, std::pair<ClientRAState, RAKeyManager>>& EnclaveState::GetClientsMap()
{
	return m_clientsMap;
}

std::map<std::string, std::string>& EnclaveState::GetClientNonceMap()
{
	return m_nonceMap;
}

DecentCryptoManager & EnclaveState::GetCryptoMgr()
{
	return m_cryptoMgr;
}
