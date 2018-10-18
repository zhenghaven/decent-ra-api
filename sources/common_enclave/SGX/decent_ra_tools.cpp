#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_INTERNAL

#include "decent_ra_tools.h"

#include <sgx_tcrypto.h>
#include <sgx_tae_service.h>

#include "DecentReplace/decent_tkey_exchange.h"

sgx_status_t enclave_init_decent_ra(const sgx_ec256_public_t *p_pub_key, int b_pse, ReportDataGenerator func, sgx_ra_derive_secret_keys_t derive_key_cb, sgx_ra_context_t *p_context)
{
	if ((!p_pub_key || !p_context))
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
	ret = decent_ra_init_ex(p_pub_key, b_pse, nullptr, func, p_context);

	if (b_pse)
	{
		sgx_close_pse_session();
	}

	if (ret != SGX_SUCCESS)
	{
		return ret;
	}

	return ret;
}

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL
