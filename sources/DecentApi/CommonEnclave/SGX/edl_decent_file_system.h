#pragma once
#ifndef EDL_DECENT_NET_H
#define EDL_DECENT_NET_H

#include <sgx_edger8r.h>

#ifdef __cplusplus
extern "C" {
#endif

	sgx_status_t SGX_CDECL ocall_decent_tools_fopen(void** retval, const char* filename, const char* mode, int is_exclusive);
	sgx_status_t SGX_CDECL ocall_decent_tools_fclose(int* retval, void* file);
	sgx_status_t SGX_CDECL ocall_decent_tools_fflush(int* retval, void* file);
	sgx_status_t SGX_CDECL ocall_decent_tools_fseek(int* retval, void* file, int64_t offset, int origin);
	sgx_status_t SGX_CDECL ocall_decent_tools_ftell(size_t* retval, void* file);
	sgx_status_t SGX_CDECL ocall_decent_tools_fread(size_t* retval, void* buffer, size_t buffer_size, void* file);
	sgx_status_t SGX_CDECL ocall_decent_tools_fwrite(size_t* retval, const void* buffer, size_t buffer_size, void* file);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // !EDL_DECENT_NET_H
