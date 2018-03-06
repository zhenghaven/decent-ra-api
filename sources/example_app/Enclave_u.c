#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_square_array_t {
	int* ms_arr;
	size_t ms_len_in_byte;
} ms_ecall_square_array_t;

typedef struct ms_ecall_add_two_int_t {
	int ms_retval;
	int ms_a;
	int ms_b;
} ms_ecall_add_two_int_t;

typedef struct ms_ocall_print_string_t {
	char* ms_str;
} ms_ocall_print_string_t;

static sgx_status_t SGX_CDECL Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * func_addr[1];
} ocall_table_Enclave = {
	1,
	{
		(void*)(uintptr_t)Enclave_ocall_print_string,
	}
};

sgx_status_t ecall_initializer_list_demo(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t ecall_square_array(sgx_enclave_id_t eid, int* arr, size_t len_in_byte)
{
	sgx_status_t status;
	ms_ecall_square_array_t ms;
	ms.ms_arr = arr;
	ms.ms_len_in_byte = len_in_byte;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t ecall_add_two_int(sgx_enclave_id_t eid, int* retval, int a, int b)
{
	sgx_status_t status;
	ms_ecall_add_two_int_t ms;
	ms.ms_a = a;
	ms.ms_b = b;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

