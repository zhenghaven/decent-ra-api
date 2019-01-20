#pragma once
#ifndef EDL_DECENT_RA_SERVER_H
#define EDL_DECENT_RA_SERVER_H

#include <sgx_edger8r.h>
#include <sgx_quote.h>

#ifdef __cplusplus
extern "C" {
#endif

	sgx_status_t ecall_decent_ra_server_init(sgx_enclave_id_t eid, sgx_status_t* retval, const sgx_spid_t* inSpid);
	sgx_status_t ecall_decent_ra_server_terminate(sgx_enclave_id_t eid);
	sgx_status_t ecall_decent_ra_server_gen_x509(sgx_enclave_id_t eid, sgx_status_t* retval, const void* ias_connector, uint64_t enclave_Id);
	sgx_status_t ecall_decent_ra_server_get_x509_pem(sgx_enclave_id_t eid, size_t* retval, char* buf, size_t buf_len);
	sgx_status_t ecall_decent_ra_server_load_const_loaded_list(sgx_enclave_id_t eid, int* retval, const char* key, const char* listJson);
	sgx_status_t ecall_decent_ra_server_proc_app_cert_req(sgx_enclave_id_t eid, sgx_status_t* retval, const char* key, void* connection);

	sgx_status_t decent_ra_get_ga(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, sgx_ec256_public_t* g_a);
	sgx_status_t decent_ra_proc_msg2_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, const sgx_ra_msg2_t* p_msg2, const sgx_target_info_t* p_qe_target, sgx_report_t* p_report, sgx_quote_nonce_t* p_nonce);
	sgx_status_t decent_ra_get_msg3_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint32_t quote_size, sgx_report_t* qe_report, sgx_ra_msg3_t* p_msg3, uint32_t msg3_size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // !EDL_DECENT_RA_SERVER_H
