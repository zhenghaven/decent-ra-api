#include <sgx_tcrypto.h>

#include <cstring>
#include <cstdlib>
#include <cstdint>

#include <cerrno>

#include "../../common/sgx_crypto_tools.h"

sgx_status_t sgx_rijndael128_cmac_msg(const sgx_cmac_128bit_key_t *p_key, const uint8_t *p_src,	uint32_t src_len, sgx_cmac_128bit_tag_t *p_mac)
{
#pragma message("!!!!!!!!!TODO: Complete this function later.!!!!!!!!!!!")

	return SGX_SUCCESS;
}

int consttime_memequal(const void *b1, const void *b2, size_t len)
{
	const unsigned char *c1 = reinterpret_cast<const unsigned char *>(b1), *c2 = reinterpret_cast<const unsigned char *>(b2);
	unsigned int res = 0;

	while (len--)
		res |= *c1++ ^ *c2++;

	/*
	* Map 0 to 1 and [1, 256) to 0 using only constant-time
	* arithmetic.
	*
	* This is not simply `!res' because although many CPUs support
	* branchless conditional moves and many compilers will take
	* advantage of them, certain compilers generate branches on
	* certain CPUs for `!res'.
	*/
	return (1 & ((res - 1) >> 8));
}
