#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL

#include "../../common/SGX/SGXRAServiceProvider.h"

/**
* \brief	Initialize Service Provider's Remote Attestation environment.
*
* \return	SGX_SUCCESS for success, otherwise please refers to sgx_error.h . *NOTE:* The error here only comes from SGX runtime.
*/
extern "C" sgx_status_t ecall_sgx_ra_sp_init()
{
	return SGXRAEnclave::ServiceProviderInit();
}

/**
* \brief	Terminate Service Provider's Remote Attestation environment.
*
*/
extern "C" void ecall_sgx_ra_sp_terminate()
{
	SGXRAEnclave::ServiceProviderTerminate();
}

/**
* \brief	Get client's public signing key.
*
* \param	context    [in]  .
* \param	outKey     [out]  .
*
* \return	SGX_SUCCESS for success, otherwise please refers to sgx_error.h .
*/
extern "C" sgx_status_t ecall_get_ra_sp_pub_sig_key(sgx_ec256_public_t* out_key)
{
	if (!out_key)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	return SGXRAEnclave::GetRASPSignPubKey(*out_key);
}

extern "C" void ecall_drop_client_ra_state(const char* server_id)
{
	SGXRAEnclave::DropClientRAState(server_id);
}

extern "C" sgx_status_t ecall_get_ias_nonce(const char* client_id, char* outStr)
{
	if (!client_id || !outStr)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	return SGXRAEnclave::GetIasNonce(client_id, outStr);
}

extern "C" sgx_status_t ecall_process_ra_msg1(const char* client_id, const sgx_ec256_public_t* in_key, const sgx_ra_msg1_t *in_msg1, sgx_ra_msg2_t *out_msg2)
{
	if (!client_id || !in_key || !in_msg1 || !out_msg2)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	return SGXRAEnclave::ProcessRaMsg1(client_id, *in_key, *in_msg1, *out_msg2);
}

extern "C" sgx_status_t ecall_process_ra_msg3(const char* client_id, 
	const uint8_t* in_msg3, uint32_t msg3_len, 
	const char* ias_report, const char* report_sign, const char* report_cert, 
	sgx_ias_report_t* out_msg4, sgx_ec256_signature_t* out_msg4_sign, 
	sgx_report_data_t* out_ori_rd)
{
	if (!client_id || !in_msg3 || !msg3_len || !ias_report || !report_sign || !report_cert || !out_msg4 || !out_msg4_sign)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	return SGXRAEnclave::ProcessRaMsg3(client_id, in_msg3, msg3_len, ias_report, report_sign, report_cert, *out_msg4, *out_msg4_sign, out_ori_rd);
}

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL
