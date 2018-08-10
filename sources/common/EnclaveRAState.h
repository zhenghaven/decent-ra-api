#pragma once

#include "DecentCryptoManager.h"

enum class ClientRAState
{
	MSG0_DONE,
	MSG1_DONE,
	ATTESTED, //MSG3_DONE,
};

enum class ServerRAState
{
	MSG0_DONE,
	MSG2_DONE,
	ATTESTED, //MSG4_DONE,
};

class EnclaveState
{
public:
	static EnclaveState& GetInstance();

	EnclaveState();
	virtual ~EnclaveState();

	virtual void Clear();

	DecentCryptoManager& GetCryptoMgr();

	const DecentCryptoManager& GetCryptoMgr() const;

private:

	DecentCryptoManager m_cryptoMgr;
};

