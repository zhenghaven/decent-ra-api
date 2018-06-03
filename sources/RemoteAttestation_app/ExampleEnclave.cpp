#include "ExampleEnclave.h"

#include <iostream>

#include <sgx_key_exchange.h>
#include <sgx_ukey_exchange.h>

#include "Enclave_u.h"
#include "../common_app/enclave_tools.h"
#include "../common/CryptoTools.h"
#include "../common/sgx_ra_msg4.h"

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

	std::cout << "Report Data: " << std::endl;
	for (int i = 0; i < 32; ++i)
	{
		std::cout << static_cast<int>(quotePtr->report_body.report_data.d[i]) << " ";
	}
	std::cout << std::endl;

	std::free(outMsg3ptr);

	res = ecall_process_ra_msg2(GetEnclaveId(), &retval, ServerID.c_str());

	return res == SGX_SUCCESS ? retval : res;
}

sgx_status_t ExampleEnclave::ProcessRAMsg3(const std::string & clientID, const sgx_ra_msg3_t & inMsg3, const uint32_t msg3Len, const std::string & iasReport, const std::string & reportSign, sgx_ra_msg4_t & outMsg4, sgx_ec256_signature_t & outMsg4Sign)
{
	sgx_status_t res = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;

	//const sgx_quote_t* quotePtr = reinterpret_cast<const sgx_quote_t*>(&(inMsg3.quote));
	res = ecall_process_ra_msg3(GetEnclaveId(), &retval, clientID.c_str(), reinterpret_cast<const uint8_t*>(&inMsg3), msg3Len, iasReport.c_str(), reportSign.c_str(), &outMsg4, &outMsg4Sign);

	return res == SGX_SUCCESS ? retval : res;
}

sgx_status_t ExampleEnclave::ProcessRAMsg4(const std::string & ServerID, const sgx_ra_msg4_t & inMsg4, const sgx_ec256_signature_t & inMsg4Sign)
{
	sgx_status_t res = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;

	//const sgx_quote_t* quotePtr = reinterpret_cast<const sgx_quote_t*>(&(inMsg3.quote));
	res = ecall_process_ra_msg4(GetEnclaveId(), &retval, ServerID.c_str(), &inMsg4, const_cast<sgx_ec256_signature_t*>(&inMsg4Sign));

	return res == SGX_SUCCESS ? retval : res;
}

sgx_status_t ExampleEnclave::TerminationClean()
{
	sgx_status_t res = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;
	res = ecall_termination_clean(GetEnclaveId(), &retval);

	return res == SGX_SUCCESS ? retval : res;
}