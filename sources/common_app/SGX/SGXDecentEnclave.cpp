#include "SGXDecentEnclave.h"

#include <iostream>

#include <sgx_ukey_exchange.h>

#include <Enclave_u.h>

#include "../common/SGX/sgx_ra_msg4.h"

#include "SGXEnclaveRuntimeException.h"

SGXDecentEnclave::SGXDecentEnclave(const sgx_spid_t& spid, const std::string& enclavePath, IASConnector iasConnector, const std::string& tokenPath) :
	//m_spid(spid),
	DecentEnclave(),
	SGXEnclaveServiceProvider(enclavePath, tokenPath, iasConnector)
{
	sgx_status_t retval = SGX_SUCCESS;
	sgx_status_t enclaveRet = ecall_decent_init(GetEnclaveId(), &retval, &spid);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_decent_init);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(retval, ecall_decent_init);
}

SGXDecentEnclave::SGXDecentEnclave(const sgx_spid_t& spid, const std::string& enclavePath, IASConnector iasConnector, const fs::path tokenPath) :
	//m_spid(spid),
	DecentEnclave(),
	SGXEnclaveServiceProvider(enclavePath, tokenPath, iasConnector)
{
	sgx_status_t retval = SGX_SUCCESS;
	sgx_status_t enclaveRet = ecall_decent_init(GetEnclaveId(), &retval, &spid);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_decent_init);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(retval, ecall_decent_init);
}

SGXDecentEnclave::SGXDecentEnclave(const sgx_spid_t& spid, const std::string& enclavePath, IASConnector iasConnector, const KnownFolderType tokenLocType, const std::string& tokenFileName) :
	//m_spid(spid),
	DecentEnclave(),
	SGXEnclaveServiceProvider(enclavePath, tokenLocType, tokenFileName, iasConnector)
{
	sgx_status_t retval = SGX_SUCCESS;
	sgx_status_t enclaveRet = ecall_decent_init(GetEnclaveId(), &retval, &spid);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_decent_init);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(retval, ecall_decent_init);
}

SGXDecentEnclave::~SGXDecentEnclave()
{
	ecall_decent_terminate(GetEnclaveId());
}

sgx_status_t SGXDecentEnclave::ProcessRAMsg0Resp(const std::string & ServerID, const sgx_ec256_public_t & inKey, int enablePSE, sgx_ra_context_t & outContextID, sgx_ra_msg1_t & outMsg1)
{
	sgx_status_t retval = SGX_SUCCESS;
	sgx_status_t enclaveRet = ecall_process_ra_msg0_resp_decent(GetEnclaveId(), &retval, ServerID.c_str(), &inKey, enablePSE, &outContextID);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_process_ra_msg0_resp);
	if (retval != SGX_SUCCESS)
	{
		return retval;
	}

	enclaveRet = sgx_ra_get_msg1(outContextID, GetEnclaveId(), decent_ra_get_ga, &outMsg1);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, sgx_ra_get_msg1);

	return SGX_SUCCESS;
}

sgx_status_t SGXDecentEnclave::ProcessRAMsg0Send(const std::string & clientID)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;
	enclaveRet = ecall_process_ra_msg0_send_decent(GetEnclaveId(), &retval, clientID.c_str());
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_process_ra_msg0_send_decent);

	return retval;
}

sgx_status_t SGXDecentEnclave::ProcessRAMsg2(const std::string & ServerID, const sgx_ra_msg2_t & inMsg2, const uint32_t & msg2Size, sgx_ra_msg3_t & outMsg3, std::vector<uint8_t>& outQuote, sgx_ra_context_t & inContextID)
{
	return SGXEnclave::ProcessRAMsg2(ServerID, inMsg2, msg2Size, outMsg3, outQuote, inContextID, decent_ra_proc_msg2_trusted, decent_ra_get_msg3_trusted);
}

sgx_status_t SGXDecentEnclave::ProcessRAMsg3(const std::string & clientID, const sgx_ra_msg3_t & inMsg3, const uint32_t msg3Len, const std::string & iasReport, const std::string & reportSign, const std::string& reportCertChain, sgx_ra_msg4_t & outMsg4, sgx_ec256_signature_t & outMsg4Sign)
{
	sgx_status_t retval = SGXEnclaveServiceProvider::ProcessRAMsg3(clientID, inMsg3, msg3Len, iasReport, reportSign, reportCertChain, outMsg4, outMsg4Sign);
	if (retval != SGX_SUCCESS)
	{
		return retval;
	}

	TransitToDecentNode(clientID, false);
	return SGX_SUCCESS;
}

sgx_status_t SGXDecentEnclave::ProcessRAMsg4(const std::string & ServerID, const sgx_ra_msg4_t & inMsg4, const sgx_ec256_signature_t & inMsg4Sign, sgx_ra_context_t inContextID)
{
	sgx_status_t retval = SGXEnclave::ProcessRAMsg4(ServerID, inMsg4, inMsg4Sign, inContextID);
	if (retval != SGX_SUCCESS)
	{
		return retval;
	}

	TransitToDecentNode(ServerID, true);
	return SGX_SUCCESS;
}

void SGXDecentEnclave::SetDecentMode(DecentNodeMode inDecentMode)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;

	enclaveRet = ecall_set_decent_mode(GetEnclaveId(), inDecentMode);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_set_decent_mode);
}

DecentNodeMode SGXDecentEnclave::GetDecentMode()
{
	DecentNodeMode res = DecentNodeMode::ROOT_SERVER;

	sgx_status_t enclaveRet = ecall_get_decent_mode(GetEnclaveId(), &res);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_get_decent_mode);

	return res;
}

sgx_status_t SGXDecentEnclave::TransitToDecentNode(const std::string & id, bool isSP)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;

	enclaveRet = ecall_transit_to_decent_node(GetEnclaveId(), &retval, id.c_str(), isSP);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_transit_to_decent_node);

	return retval;
}

sgx_status_t SGXDecentEnclave::GetProtocolSignKey(const std::string & id, sgx_ec256_private_t & outPriKey, sgx_aes_gcm_128bit_tag_t & outPriKeyMac, sgx_ec256_public_t & outPubKey, sgx_aes_gcm_128bit_tag_t & outPubKeyMac)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;

	enclaveRet = ecall_get_protocol_sign_key(GetEnclaveId(), &retval, id.c_str(), &outPriKey, &outPriKeyMac, &outPubKey, &outPubKeyMac);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_get_protocol_sign_key);

	return retval;
}

sgx_status_t SGXDecentEnclave::SetProtocolSignKey(const std::string & id, const sgx_ec256_private_t & inPriKey, const sgx_aes_gcm_128bit_tag_t & inPriKeyMac, const sgx_ec256_public_t & inPubKey, const sgx_aes_gcm_128bit_tag_t & inPubKeyMac)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;

	enclaveRet = ecall_set_protocol_sign_key(GetEnclaveId(), &retval, id.c_str(), &inPriKey, &inPriKeyMac, &inPubKey, &inPubKeyMac);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_set_protocol_sign_key);

	return retval;
}

sgx_status_t SGXDecentEnclave::GetProtocolKeySigned(const std::string & id, const sgx_ec256_public_t & inSignKey, const sgx_ec256_public_t & inEncrKey, sgx_ec256_signature_t & outSignSign, sgx_aes_gcm_128bit_tag_t & outSignSignMac, sgx_ec256_signature_t & outEncrSign, sgx_aes_gcm_128bit_tag_t & outEncrSignMac)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;

	enclaveRet = ecall_get_protocol_key_signed(GetEnclaveId(), &retval, id.c_str(), &inSignKey, &inEncrKey, &outSignSign, &outSignSignMac, &outEncrSign, &outEncrSignMac);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_get_protocol_key_signed);

	return retval;
}

sgx_status_t SGXDecentEnclave::SetKeySigns(const std::string & id, const sgx_ec256_signature_t & inSignSign, const sgx_aes_gcm_128bit_tag_t & inSignSignMac, const sgx_ec256_signature_t & inEncrSign, const sgx_aes_gcm_128bit_tag_t & inEncrSignMac)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;

	enclaveRet = ecall_set_key_signs(GetEnclaveId(), &retval, id.c_str(), &inSignSign, &inSignSignMac, &inEncrSign, &inEncrSignMac);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_set_key_signs);

	return retval;
}

sgx_status_t SGXDecentEnclave::ProcessDecentMsg0(const std::string & id, const sgx_ec256_public_t & inSignKey, const sgx_ec256_signature_t & inSignSign, const sgx_ec256_public_t & inEncrKey, const sgx_ec256_signature_t & inEncrSign)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;

	enclaveRet = ecall_proc_decent_msg0(GetEnclaveId(), &retval, id.c_str(), &inSignKey, &inSignSign, &inEncrKey, &inEncrSign);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_proc_decent_msg0);

	return retval;
}
