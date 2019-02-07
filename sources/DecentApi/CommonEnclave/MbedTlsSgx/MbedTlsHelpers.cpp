//#if ENCLAVE_PLATFORM_SGX

#include "../../Common/MbedTls/MbedTlsHelpers.h"

#include <sgx_trts.h>

using namespace Decent::MbedTlsHelper;

Drbg::Drbg() :
	m_state(nullptr)
{
}

Drbg::~Drbg()
{
}

bool Drbg::Rand(void* buf, const size_t size)
{
	return CallBack(nullptr, static_cast<unsigned char *>(buf), size) == 0;
}

int Drbg::CallBack(void * ctx, unsigned char * buf, size_t len)
{
	return sgx_read_rand(buf, len) == SGX_SUCCESS ? 0 : -1;
}

//#endif //ENCLAVE_PLATFORM_SGX
