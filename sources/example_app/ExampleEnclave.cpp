#include "ExampleEnclave.h"

#include <iostream>

#include "Enclave_u.h"

void ExampleEnclave::TestEnclaveFunctions()
{
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;

	// Example for initializer_list:
	sgx_enclave_id_t eid = SGXEnclave::GetEnclaveId();
	ret = ecall_initializer_list_demo(eid);
	if (ret != SGX_SUCCESS)
		abort();

	std::cout << std::endl;

	int addRes = 0;
	// Example for adding two number:
	ret = ecall_add_two_int(SGXEnclave::GetEnclaveId(), &addRes, 123, 456);
	if (ret != SGX_SUCCESS)
		abort();
	std::cout << "Adding demo result: " << addRes << ". " << std::endl;

	std::cout << std::endl;

	std::vector<int> testArr = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
	ret = ecall_square_array(SGXEnclave::GetEnclaveId(), testArr.data(), testArr.size() * sizeof(int));
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
