#include "../../Common/SGX/RaProcessorSp.h"

extern "C" sgx_status_t ecall_decent_sgx_decentralized_init(const sgx_spid_t* in_spid)
{
	if (!in_spid)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	return SGX_SUCCESS;
}
