#include "../../common/SGX/SGXRAServiceProvider.h"

extern "C" sgx_status_t ecall_init_ra_sp_environment()
{
	return SGXRAEnclave::InitRaSpEnvironment();
}

extern "C" sgx_status_t ecall_get_ias_nonce(const char* clientID, char* outStr)
{
	return SGXRAEnclave::GetIasNonce(clientID, outStr);
}

/**
* \brief	Get client's public encryption key.
*
* \param	context    [in]  .
* \param	outKey     [out]  .
*
* \return	SGX_SUCCESS for success, otherwise please refers to sgx_error.h .
*/
extern "C" sgx_status_t ecall_get_ra_sp_pub_enc_key(sgx_ra_context_t context, sgx_ec256_public_t* outKey)
{
	return SGXRAEnclave::GetRASPEncrPubKey(context, outKey);
}

/**
* \brief	Get client's public signing key.
*
* \param	context    [in]  .
* \param	outKey     [out]  .
*
* \return	SGX_SUCCESS for success, otherwise please refers to sgx_error.h .
*/
extern "C" sgx_status_t ecall_get_ra_sp_pub_sig_key(sgx_ec256_public_t* outKey)
{
	return SGXRAEnclave::GetRASPSignPubKey(outKey);
}

extern "C" sgx_status_t ecall_process_ra_msg0_send(const char* clientID)
{
	return SGXRAEnclave::ProcessRaMsg0Send(clientID);
}

extern "C" sgx_status_t ecall_process_ra_msg1(const char* clientID, const sgx_ra_msg1_t *inMsg1, sgx_ra_msg2_t *outMsg2)
{
	return SGXRAEnclave::ProcessRaMsg1(clientID, inMsg1, outMsg2);
}

extern "C" sgx_status_t ecall_process_ra_msg3(const char* clientID, const uint8_t* inMsg3, uint32_t msg3Len, const char* iasReport, const char* reportSign, const char* reportCert, sgx_ra_msg4_t* outMsg4, sgx_ec256_signature_t* outMsg4Sign)
{
	return SGXRAEnclave::ProcessRaMsg3(clientID, inMsg3, msg3Len, iasReport, reportSign, reportCert, outMsg4, outMsg4Sign);
}
