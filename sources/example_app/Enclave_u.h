#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));

sgx_status_t ecall_initializer_list_demo(sgx_enclave_id_t eid);
sgx_status_t ecall_square_array(sgx_enclave_id_t eid, int* arr, size_t len_in_byte);
sgx_status_t ecall_add_two_int(sgx_enclave_id_t eid, int* retval, int a, int b);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
