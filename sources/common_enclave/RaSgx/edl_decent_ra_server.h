#pragma once
#ifndef EDL_DECENT_RA_SERVER_H
#define EDL_DECENT_RA_SERVER_H

#include <sgx_edger8r.h>
#include <sgx_key_exchange.h>

#ifdef __cplusplus
extern "C" {
#endif

	sgx_status_t SGX_CDECL ocall_decent_ra_server_ra_get_msg1(int* retval, uint64_t enclave_id, uint32_t ra_ctx, sgx_ra_msg1_t* msg1);
	sgx_status_t SGX_CDECL ocall_decent_ra_server_ra_proc_msg2(size_t* retval, uint64_t enclave_id, uint32_t ra_ctx, const sgx_ra_msg2_t* msg2, size_t msg2_size, uint8_t** out_msg3);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // !EDL_DECENT_RA_SERVER_H
