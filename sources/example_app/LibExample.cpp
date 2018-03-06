#include "LibExample.h"

#include <stdlib.h>
#include <stdio.h>

#include <iostream>
#include <vector>

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

	std::cout << std::endl;

	int addRes = 0;
	// Example for adding two number:
	ret = ecall_add_two_int(global_eid, &addRes, 123, 456);
	if (ret != SGX_SUCCESS)
		abort();
	std::cout << "Adding demo result: " << addRes << ". " << std::endl;

	std::cout << std::endl;

	std::vector<int> testArr = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
	ret = ecall_square_array(global_eid, testArr.data(), testArr.size() * sizeof(int));
	if (ret != SGX_SUCCESS)
		abort();
	std::cout << "Square array demo result:";
	for (int v : testArr)
	{
		std::cout << " " << v;
	}

	std::cout << std::endl;

	std::cout << std::endl;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
	/* Proxy/Bridge will check the length and null-terminate
	* the input string to prevent buffer overflow.
	*/
	printf("%s", str);
}