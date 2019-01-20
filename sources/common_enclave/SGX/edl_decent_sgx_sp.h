#pragma once
#ifndef EDL_DECENT_SGX_SP_H
#define EDL_DECENT_SGX_SP_H

#include <sgx_edger8r.h>
#include <sgx_key_exchange.h>

#ifdef __cplusplus
extern "C" {
#endif

	sgx_status_t SGX_CDECL ocall_decent_ias_get_revoc_list(int* retval, const void* connector_ptr, const sgx_epid_group_id_t* gid, char** outRevcList, size_t* out_size);
	sgx_status_t SGX_CDECL ocall_decent_ias_get_quote_report(int* retval, const void* connector_ptr, const sgx_ra_msg3_t* msg3, size_t msg3_size, const char* nonce, int pse_enabled, char** out_report, size_t* report_size, char** out_sign, size_t* sign_size, char** out_cert, size_t* cert_size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // !EDL_DECENT_SGX_SP_H
