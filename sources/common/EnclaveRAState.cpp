#include "EnclaveRAState.h"

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
}

DecentCryptoManager & EnclaveState::GetCryptoMgr()
{
	return m_cryptoMgr;
}

const DecentCryptoManager & EnclaveState::GetCryptoMgr() const
{
	return m_cryptoMgr;
}
