#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENTRALIZED_ENCLAVE_INTERNAL

extern "C" sgx_status_t ecall_decentralized_init(const sgx_spid_t* in_spid)
{
	if (!in_spid)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}
	SgxRaProcessorSp::SetSpid(*inSpid);

	return SGX_SUCCESS;
}

#endif // USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENTRALIZED_ENCLAVE_INTERNAL
