#pragma once
#ifndef EDL_DECENT_TOOLS_H
#define EDL_DECENT_TOOLS_H

#include <ctime>

#include <sgx_edger8r.h>

#ifdef __cplusplus
extern "C" {
#endif

	sgx_status_t SGX_CDECL ocall_decent_tools_print_string(const char* str);
	sgx_status_t SGX_CDECL ocall_decent_tools_print_string_i(const char* str);
	sgx_status_t SGX_CDECL ocall_decent_tools_print_string_w(const char* str);
	sgx_status_t SGX_CDECL ocall_decent_tools_del_buf_char(char* ptr);
	sgx_status_t SGX_CDECL ocall_decent_tools_del_buf_uint8(uint8_t* ptr);
	sgx_status_t SGX_CDECL ocall_decent_tools_get_sys_time(time_t* timer);
	sgx_status_t SGX_CDECL ocall_decent_tools_get_sys_utc_time(const time_t* timer, struct tm* out_time);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // !EDL_DECENT_TOOLS_H
