//#if ENCLAVE_PLATFORM_SGX

#include "../../Common/MbedTls/Drbg.h"
#include "../../Common/MbedTls/RuntimeException.h"

#include <sgx_trts.h>

using namespace Decent::MbedTlsObj;

Drbg::Drbg() :
	m_state(nullptr)
{
}

Drbg::~Drbg()
{
}

void Drbg::Rand(void* buf, const size_t size)
{
	if (CallBack(nullptr, static_cast<unsigned char *>(buf), size) != 0)
	{
		throw RuntimeException("SGX failed to generate random number!");
	}
}

int Drbg::CallBack(void * ctx, unsigned char * buf, size_t len)
{
	return sgx_read_rand(buf, len) == SGX_SUCCESS ? 0 : -1;
}

//#endif //ENCLAVE_PLATFORM_SGX
