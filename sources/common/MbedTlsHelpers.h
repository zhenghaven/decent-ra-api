#pragma once

namespace MbedTlsHelper
{
	void MbedTlsHelperDrbgInit(void *& ctx);

	int MbedTlsHelperDrbgRandom(void * ctx, unsigned char * output, size_t output_len);

	void MbedTlsHelperDrbgFree(void *& ctx);
}
