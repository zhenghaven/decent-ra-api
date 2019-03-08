#pragma once
#ifndef EDL_DECENT_NET_H
#define EDL_DECENT_NET_H

#include <sgx_edger8r.h>

#ifdef __cplusplus
extern "C" {
#endif

	sgx_status_t SGX_CDECL ocall_decent_net_cnet_send_pack(int* retval, void* ptr, const char* msg, size_t size);
	sgx_status_t SGX_CDECL ocall_decent_net_cnet_recv_pack(int* retval, size_t* recv_size, void* ptr, char** msg);
	sgx_status_t SGX_CDECL ocall_decent_net_cnet_send_and_recv_pack(int* retval, void* ptr, const char* in_msg, size_t in_size, char** out_msg, size_t* out_size);
	sgx_status_t SGX_CDECL ocall_decent_net_cnet_send_raw(int* retval, size_t* sent_size, void* ptr, const char* msg, size_t size);
	sgx_status_t SGX_CDECL ocall_decent_net_cnet_recv_raw(int* retval, size_t* recv_size, void* ptr, char* buf, size_t buf_size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // !EDL_DECENT_NET_H
