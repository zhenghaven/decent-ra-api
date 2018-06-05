#include "ExampleEnclave.h"

#include <iostream>

#include <sgx_key_exchange.h>
#include <sgx_ukey_exchange.h>
#include <sgx_uae_service.h>

#include "Enclave_u.h"
#include "../common_app/enclave_tools.h"
#include "../common/CryptoTools.h"
#include "../common/sgx_ra_msg4.h"

sgx_status_t ExampleEnclave::GetRASignPubKey(sgx_ec256_public_t & outKey)
{
	sgx_status_t res = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;
	
	res = ecall_get_ra_pub_sig_key(GetEnclaveId(), &retval, 0, &outKey);
	//std::string tmp = SerializePubKey(outKey);

	return res == SGX_SUCCESS ? retval : res;
}

//sgx_status_t ExampleEnclave::GetRAEncrPubKey(sgx_ec256_public_t & outKey)
//{
//	sgx_status_t res = SGX_SUCCESS;
//	sgx_status_t retval = SGX_SUCCESS;
//
//	res = ecall_get_ra_pub_enc_key(GetEnclaveId(), &retval, 0, &outKey);
//	//std::string tmp = SerializePubKey(outKey);
//
//	return res == SGX_SUCCESS ? retval : res;
//}

sgx_status_t ExampleEnclave::InitRAEnvironment()
{
	sgx_status_t res = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;
	res = ecall_init_ra_environment(GetEnclaveId(), &retval);
	if (res != SGX_SUCCESS || retval != SGX_SUCCESS)
	{
		return res == SGX_SUCCESS ? retval : res;
	}

	//Get extended group ID.
	res = sgx_get_extended_epid_group_id(&m_exGroupID);
	if (res != SGX_SUCCESS)
	{
		return res;
	}

	//Get Sign public key.
	sgx_ec256_public_t signPubKey;
	res = GetRASignPubKey(signPubKey);
	if (res != SGX_SUCCESS)
	{
		return res;
	}
	m_raSenderID = SerializePubKey(signPubKey);

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

	std::cout << "In Process RA Msg 0 Resp: " << std::endl;
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

	res = ecall_process_ra_msg2(GetEnclaveId(), &retval, ServerID.c_str(), inContextID);

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

sgx_status_t ExampleEnclave::ProcessRAMsg4(const std::string & ServerID, const sgx_ra_msg4_t & inMsg4, const sgx_ec256_signature_t & inMsg4Sign, sgx_ra_context_t inContextID)
{
	sgx_status_t res = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;

	//const sgx_quote_t* quotePtr = reinterpret_cast<const sgx_quote_t*>(&(inMsg3.quote));
	res = ecall_process_ra_msg4(GetEnclaveId(), &retval, ServerID.c_str(), &inMsg4, const_cast<sgx_ec256_signature_t*>(&inMsg4Sign), inContextID);

	return res == SGX_SUCCESS ? retval : res;
}

sgx_status_t ExampleEnclave::TerminationClean()
{
	sgx_status_t res = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;
	res = ecall_termination_clean(GetEnclaveId(), &retval);

	return res == SGX_SUCCESS ? retval : res;
}

void ExampleEnclave::SetDecentMode(DecentNodeMode inDecentMode)
{
	sgx_status_t enclaveRes = SGX_SUCCESS;

	enclaveRes = ecall_set_decent_mode(GetEnclaveId(), inDecentMode);

	m_lastStatus = enclaveRes;
}

DecentNodeMode ExampleEnclave::GetDecentMode()
{
	DecentNodeMode res = DecentNodeMode::ROOT_SERVER;

	sgx_status_t enclaveRes = SGX_SUCCESS;

	enclaveRes = ecall_get_decent_mode(GetEnclaveId(), &res);

	m_lastStatus = enclaveRes;
	return res;
}

sgx_status_t ExampleEnclave::GetProtocolSignKey(const std::string & id, sgx_ec256_private_t & outPriKey, sgx_aes_gcm_128bit_tag_t & outPriKeyMac, sgx_ec256_public_t & outPubKey, sgx_aes_gcm_128bit_tag_t & outPubKeyMac)
{
	sgx_status_t res = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;

	res = ecall_get_protocol_sign_key(GetEnclaveId(), &retval, id.c_str(), &outPriKey, &outPriKeyMac, &outPubKey, &outPubKeyMac);

	return res == SGX_SUCCESS ? retval : res;
}

sgx_status_t ExampleEnclave::GetProtocolEncrKey(const std::string & id, sgx_ec256_private_t & outPriKey, sgx_aes_gcm_128bit_tag_t & outPriKeyMac, sgx_ec256_public_t & outPubKey, sgx_aes_gcm_128bit_tag_t & outPubKeyMac)
{
	sgx_status_t res = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;

	res = ecall_get_protocol_encr_key(GetEnclaveId(), &retval, id.c_str(), &outPriKey, &outPriKeyMac, &outPubKey, &outPubKeyMac);

	return res == SGX_SUCCESS ? retval : res;
}

sgx_status_t ExampleEnclave::SetProtocolSignKey(const std::string & id, const sgx_ec256_private_t & inPriKey, const sgx_aes_gcm_128bit_tag_t & inPriKeyMac, const sgx_ec256_public_t & inPubKey, const sgx_aes_gcm_128bit_tag_t & inPubKeyMac)
{
	sgx_status_t res = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;

	res = ecall_set_protocol_sign_key(GetEnclaveId(), &retval, id.c_str(), &inPriKey, &inPriKeyMac, &inPubKey, &inPubKeyMac);

	return res == SGX_SUCCESS ? retval : res;
}

sgx_status_t ExampleEnclave::SetProtocolEncrKey(const std::string & id, const sgx_ec256_private_t & inPriKey, const sgx_aes_gcm_128bit_tag_t & inPriKeyMac, const sgx_ec256_public_t & inPubKey, const sgx_aes_gcm_128bit_tag_t & inPubKeyMac)
{
	sgx_status_t res = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;

	res = ecall_set_protocol_encr_key(GetEnclaveId(), &retval, id.c_str(), &inPriKey, &inPriKeyMac, &inPubKey, &inPubKeyMac);

	return res == SGX_SUCCESS ? retval : res;
}

sgx_status_t ExampleEnclave::GetProtocolKeySigned(const std::string & id, const sgx_ec256_public_t & inSignKey, const sgx_ec256_public_t & inEncrKey, sgx_ec256_signature_t & outSignSign, sgx_aes_gcm_128bit_tag_t & outSignSignMac, sgx_ec256_signature_t & outEncrSign, sgx_aes_gcm_128bit_tag_t & outEncrSignMac)
{
	sgx_status_t res = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;

	res = ecall_get_protocol_key_signed(GetEnclaveId(), &retval, id.c_str(), &inSignKey, &inEncrKey, &outSignSign, &outSignSignMac, &outEncrSign, &outEncrSignMac);

	return res == SGX_SUCCESS ? retval : res;
}

sgx_status_t ExampleEnclave::SetKeySigns(const std::string & id, const sgx_ec256_signature_t & inSignSign, const sgx_aes_gcm_128bit_tag_t & inSignSignMac, const sgx_ec256_signature_t & inEncrSign, const sgx_aes_gcm_128bit_tag_t & inEncrSignMac)
{
	sgx_status_t res = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;

	res = ecall_set_key_signs(GetEnclaveId(), &retval, id.c_str(), &inSignSign, &inSignSignMac, &inEncrSign, &inEncrSignMac);

	return res == SGX_SUCCESS ? retval : res;
}

void ExampleEnclave::GetKeySigns(sgx_ec256_signature_t & outSignSign, sgx_ec256_signature_t & outEncrSign)
{
	sgx_status_t res = SGX_SUCCESS;

	res = ecall_get_key_signs(GetEnclaveId(), &outSignSign, &outEncrSign);

	m_lastStatus = res;
}

sgx_status_t ExampleEnclave::ProcessDecentMsg0(const std::string & id, const sgx_ec256_public_t & inSignKey, const sgx_ec256_signature_t & inSignSign, const sgx_ec256_public_t & inEncrKey, const sgx_ec256_signature_t & inEncrSign)
{
	sgx_status_t res = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;

	res = ecall_proc_decent_msg0(GetEnclaveId(), &retval, id.c_str(), &inSignKey, &inSignSign, &inEncrKey, &inEncrSign);

	return res == SGX_SUCCESS ? retval : res;
}

sgx_status_t ExampleEnclave::GetSimpleSecret(const std::string & id, uint64_t & secret, sgx_aes_gcm_128bit_tag_t & outSecretMac)
{
	sgx_status_t res = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;

	res = ecall_get_simple_secret(GetEnclaveId(), &retval, id.c_str(), &secret, &outSecretMac);

	return res == SGX_SUCCESS ? retval : res;
}

sgx_status_t ExampleEnclave::ProcessSimpleSecret(const std::string & id, const uint64_t & secret, const sgx_aes_gcm_128bit_tag_t & inSecretMac)
{
	sgx_status_t res = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;

	res = ecall_proc_simple_secret(GetEnclaveId(), &retval, id.c_str(), &secret, &inSecretMac);

	return res == SGX_SUCCESS ? retval : res;
}
