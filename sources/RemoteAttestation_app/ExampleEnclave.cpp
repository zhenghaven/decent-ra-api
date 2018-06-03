#include "ExampleEnclave.h"

#include <iostream>

#include <sgx_key_exchange.h>
#include <sgx_ukey_exchange.h>

#include "Enclave_u.h"
#include "../common_app/enclave_tools.h"
#include "../common/CryptoTools.h"

sgx_status_t ExampleEnclave::GetRAPublicKey(sgx_ec256_public_t & outKey)
{
	sgx_status_t res = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;
	
	res = ecall_get_ra_pub_keys(GetEnclaveId(), &retval, &outKey);
	//std::string tmp = SerializePubKey(outKey);

	return res == SGX_SUCCESS ? retval : res;
}

sgx_status_t ExampleEnclave::InitRAEnvironment()
{
	sgx_status_t res = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;
	res = ecall_init_ra_environment(GetEnclaveId(), &retval);

	return res == SGX_SUCCESS ? retval : res;
}

sgx_status_t ExampleEnclave::ProcessRAMsg0Send(const std::string & clientID)
{
	sgx_status_t res = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;
	res = ecall_process_ra_msg0_send(GetEnclaveId(), &retval, clientID.c_str());

	return res == SGX_SUCCESS ? retval : res;
}

sgx_status_t ExampleEnclave::ProcessRAMsg0Resp(const std::string & ServerID, const sgx_ec256_public_t & inKey, int enablePSE, sgx_ra_context_t & outContextID, sgx_ra_msg1_t & outMsg1)
{
	sgx_status_t res = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;
	res = ecall_process_ra_msg0_resp(GetEnclaveId(), &retval, ServerID.c_str(), &inKey, enablePSE, &outContextID);
	if (res != SGX_SUCCESS || retval != SGX_SUCCESS)
	{
		return res == SGX_SUCCESS ? retval : res;
	}

	res = sgx_ra_get_msg1(outContextID, GetEnclaveId(), sgx_ra_get_ga, &outMsg1);

	std::cout << "In Process RA Msg 1: " << std::endl;
	std::cout << "g_a: " << SerializePubKey(outMsg1.g_a) << std::endl << std::endl;

	return res == SGX_SUCCESS ? retval : res;
}

sgx_status_t ExampleEnclave::ProcessRAMsg1(const std::string & clientID, const sgx_ra_msg1_t & inMsg1, sgx_ra_msg2_t & outMsg2)
{
	sgx_status_t res = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;
	res = ecall_process_ra_msg1(GetEnclaveId(), &retval, clientID.c_str(), &inMsg1, &outMsg2);

	return res == SGX_SUCCESS ? retval : res;
}

sgx_status_t ExampleEnclave::ProcessRAMsg2(const std::string& ServerID, const sgx_ra_msg2_t & inMsg2, const uint32_t& msg2Size, sgx_ra_msg3_t& outMsg3, std::vector<uint8_t>& outQuote, sgx_ra_context_t& inContextID)
{
	sgx_status_t res = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;
	sgx_ra_msg3_t* outMsg3ptr = nullptr;
	uint32_t msg3Size = 0;

	res = sgx_ra_proc_msg2(inContextID, GetEnclaveId(), sgx_ra_proc_msg2_trusted, sgx_ra_get_msg3_trusted, &inMsg2, msg2Size, &outMsg3ptr, &msg3Size);

	if (res != SGX_SUCCESS)
	{
		return res;
	}
	if (msg3Size == 0 || msg3Size <= sizeof(sgx_ra_msg3_t))
	{
		return SGX_ERROR_UNEXPECTED;
	}

	sgx_quote_t* quotePtr = reinterpret_cast<sgx_quote_t*>(outMsg3ptr->quote);
	memcpy(&outMsg3, outMsg3ptr, sizeof(sgx_ra_msg3_t));
	outQuote.resize(sizeof(sgx_quote_t) + quotePtr->signature_len);
	memcpy(&outQuote[0], quotePtr, sizeof(sgx_quote_t) + quotePtr->signature_len);

	std::cout << "In Process RA Msg 2: " << std::endl;
	std::cout << "g_a: " << SerializePubKey(outMsg3.g_a) << std::endl;
	std::cout << "g_b: " << SerializePubKey(inMsg2.g_b) << std::endl << std::endl;

	std::free(outMsg3ptr);

	res = ecall_process_ra_msg2(GetEnclaveId(), &retval, ServerID.c_str());

	return res == SGX_SUCCESS ? retval : res;
}

sgx_status_t ExampleEnclave::TerminationClean()
{
	sgx_status_t res = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;
	res = ecall_termination_clean(GetEnclaveId(), &retval);

	return res == SGX_SUCCESS ? retval : res;
}

//void ExampleEnclave::TestEnclaveFunctions()
//{
//	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
//
//	// Example for initializer_list:
//	sgx_enclave_id_t eid = SGXEnclave::GetEnclaveId();
//	ret = ecall_initializer_list_demo(eid);
//	if (ret != SGX_SUCCESS)
//		abort();
//
//	std::cout << std::endl;
//
//	int addRes = 0;
//	// Example for adding two number:
//	ret = ecall_add_two_int(SGXEnclave::GetEnclaveId(), &addRes, 123, 456);
//	if (ret != SGX_SUCCESS)
//		abort();
//	std::cout << "Adding demo result: " << addRes << ". " << std::endl;
//
//	std::cout << std::endl;
//
//	std::vector<int> testArr = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
//	ret = ecall_square_array(SGXEnclave::GetEnclaveId(), testArr.data(), testArr.size() * sizeof(int));
//	if (ret != SGX_SUCCESS)
//		abort();
//	std::cout << "Square array demo result:";
//	for (int v : testArr)
//	{
//		std::cout << " " << v;
//	}
//
//	std::cout << std::endl;
//
//	std::cout << std::endl;
//}
