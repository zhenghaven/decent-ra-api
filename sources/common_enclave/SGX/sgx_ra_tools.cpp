#include "sgx_ra_tools.h"

#include <sgx_tcrypto.h>
#include <sgx_key_exchange.h>
//#include <sgx_tkey_exchange.h>
#include "decent_tkey_exchange.h"

sgx_status_t enclave_init_ra(const sgx_ec256_public_t *p_pub_key, int b_pse, const sgx_ec256_private_t *p_a, const sgx_ec256_public_t *p_g_a, sgx_ra_derive_secret_keys_t derive_key_cb, sgx_ra_context_t *p_context)
{
	if ((!p_pub_key || !p_context) ||
		(p_a != nullptr && p_g_a == nullptr) ||
		(p_a == nullptr && p_g_a != nullptr))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	// isv enclave call to trusted key exchange library.
	sgx_status_t ret;
	if (b_pse)
	{
		//int busy_retry_times = 2; do {} while (ret == SGX_ERROR_BUSY && busy_retry_times--);
		ret = sgx_create_pse_session();
		if (ret != SGX_SUCCESS)
			return ret;
	}
	ret = decent_ra_init_ex(p_pub_key, b_pse, nullptr, p_context);

	if (b_pse)
	{
		sgx_close_pse_session();
	}

	if (ret != SGX_SUCCESS)
	{
		return ret;
	}

	if (p_a && p_g_a)
	{
		ret = decent_ra_set_key_pair(*p_context, p_a, p_g_a);
	}

	return ret;
}
