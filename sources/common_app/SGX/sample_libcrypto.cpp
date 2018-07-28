#include <sgx_tcrypto.h>

#include <cstring>
#include <cstdlib>
#include <cstdint>

#include <cerrno>

sgx_status_t sgx_rijndael128_cmac_msg(const sgx_cmac_128bit_key_t *p_key, const uint8_t *p_src,	uint32_t src_len, sgx_cmac_128bit_tag_t *p_mac)
{
#pragma message("!!!!!!!!!TODO: Complete this function later.!!!!!!!!!!!")

	return SGX_SUCCESS;
}
