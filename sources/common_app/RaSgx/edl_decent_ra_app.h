#pragma once
#ifndef EDL_DECENT_RA_APP_H
#define EDL_DECENT_RA_APP_H

#include <sgx_edger8r.h>

#ifdef __cplusplus
extern "C" {
#endif

	sgx_status_t ecall_decent_ra_app_get_x509_pem(sgx_enclave_id_t eid, size_t* retval, char* buf, size_t buf_len);
	sgx_status_t ecall_decent_ra_app_init(sgx_enclave_id_t eid, sgx_status_t* retval, void* connection);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // !EDL_DECENT_RA_APP_H
