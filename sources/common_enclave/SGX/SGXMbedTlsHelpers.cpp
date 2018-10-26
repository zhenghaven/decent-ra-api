#include "../common/MbedTlsHelpers.h"

#include <sgx_trts.h>

void MbedTlsHelper::DrbgInit(void *& ctx)
{
}

int MbedTlsHelper::DrbgRandom(void * ctx, unsigned char * output, size_t output_len)
{
	if (!output ||
		sgx_read_rand(output, output_len) != SGX_SUCCESS)
	{
		return -1;
	}

	return 0;
}

void MbedTlsHelper::DrbgFree(void *& ctx)
{
}
