#pragma once
#ifndef EDL_DECENT_SGX_SP_H
#define EDL_DECENT_SGX_SP_H

#include <sgx_edger8r.h>
#include <sgx_key_exchange.h>

#ifdef __cplusplus
extern "C" {
#endif

	sgx_status_t ecall_decent_sgx_sp_get_pub_sign_key(sgx_enclave_id_t eid, int* retval, sgx_ec256_public_t* out_key);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // !EDL_DECENT_SGX_SP_H
