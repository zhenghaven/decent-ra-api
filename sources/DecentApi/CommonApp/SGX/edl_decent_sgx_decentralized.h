#pragma once
#ifndef EDL_DECENT_SGX_DECENTRALIZED_H
#define EDL_DECENT_SGX_DECENTRALIZED_H

#include <sgx_edger8r.h>
#include <sgx_key_exchange.h>

#ifdef __cplusplus
extern "C" {
#endif

	sgx_status_t ecall_decent_sgx_decentralized_init(sgx_enclave_id_t eid, sgx_status_t* retval, const sgx_spid_t* inSpid);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // !EDL_DECENT_SGX_DECENTRALIZED_H
