#include "LibExample.h"

#include <stdlib.h>
#include <stdio.h>

#include <sgx_error.h>       /* sgx_status_t */
#include <sgx_eid.h>     /* sgx_enclave_id_t */

#include "Enclave_u.h"

extern sgx_enclave_id_t global_eid;    /* global enclave id */

void ecall_example_function_vec(void)
{
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;

	// Example for initializer_list:
	ret = ecall_initializer_list_demo(global_eid);
	if (ret != SGX_SUCCESS)
		abort();
}

/* OCall functions */
void ocall_print_string(const char *str)
{
	/* Proxy/Bridge will check the length and null-terminate
	* the input string to prevent buffer overflow.
	*/
	printf("%s", str);
}