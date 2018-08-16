#pragma once

#include <sgx_tcrypto.h>

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
