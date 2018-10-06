#include "../common/MbedTlsHelpers.h"

#include <sgx_trts.h>

void MbedTlsHelper::MbedTlsHelperDrbgInit(void *& ctx)
{
}

int MbedTlsHelper::MbedTlsHelperDrbgRandom(void * ctx, unsigned char * output, size_t output_len)
{
	if (!output ||
		sgx_read_rand(output, output_len) != SGX_SUCCESS)
	{
		return -1;
	}

	return 0;
}

void MbedTlsHelper::MbedTlsHelperDrbgFree(void *& ctx)
{
}
