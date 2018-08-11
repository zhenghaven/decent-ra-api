#include "SGXDecentEnclave.h"

#include <iostream>

#include <Enclave_u.h>

#include "../common/SGX/sgx_ra_msg4.h"

#include "SGXEnclaveRuntimeException.h"

SGXDecentEnclave::SGXDecentEnclave(const sgx_spid_t& spid, const std::string& enclavePath, IASConnector iasConnector, const std::string& tokenPath) :
	SGXEnclaveServiceProvider(enclavePath, tokenPath, iasConnector),
	m_spid(spid)
{
}

SGXDecentEnclave::SGXDecentEnclave(const sgx_spid_t& spid, const std::string& enclavePath, IASConnector iasConnector, const fs::path tokenPath) :
	SGXEnclaveServiceProvider(enclavePath, tokenPath, iasConnector),
	m_spid(spid)
{
}

SGXDecentEnclave::SGXDecentEnclave(const sgx_spid_t& spid, const std::string& enclavePath, IASConnector iasConnector, const KnownFolderType tokenLocType, const std::string& tokenFileName) :
	SGXEnclaveServiceProvider(enclavePath, tokenLocType, tokenFileName, iasConnector),
	m_spid(spid)
{
}

SGXDecentEnclave::~SGXDecentEnclave()
{
}

sgx_status_t SGXDecentEnclave::ProcessRAMsg3(const std::string & clientID, const sgx_ra_msg3_t & inMsg3, const uint32_t msg3Len, const std::string & iasReport, const std::string & reportSign, const std::string& reportCertChain, sgx_ra_msg4_t & outMsg4, sgx_ec256_signature_t & outMsg4Sign)
{
	sgx_status_t retval = SGXEnclaveServiceProvider::ProcessRAMsg3(clientID, inMsg3, msg3Len, iasReport, reportSign, reportCertChain, outMsg4, outMsg4Sign);
	if (retval != SGX_SUCCESS)
	{
		return retval;
	}

	TransitToDecentNode(clientID);
	return SGX_SUCCESS;
}

sgx_status_t SGXDecentEnclave::ProcessRAMsg4(const std::string & ServerID, const sgx_ra_msg4_t & inMsg4, const sgx_ec256_signature_t & inMsg4Sign, sgx_ra_context_t inContextID)
{
	sgx_status_t retval = SGXEnclave::ProcessRAMsg4(ServerID, inMsg4, inMsg4Sign, inContextID);
	if (retval != SGX_SUCCESS)
	{
		return retval;
	}

	TransitToDecentNode(ServerID);
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

sgx_status_t SGXDecentEnclave::InitDecentRAEnvironment()
{
	return InitDecentRAEnvironment(m_spid);
}

sgx_status_t SGXDecentEnclave::InitDecentRAEnvironment(const sgx_spid_t & inSpid)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;

	enclaveRet = ecall_init_decent_ra_environment(GetEnclaveId(), &retval, &inSpid);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_init_decent_ra_environment);

	return retval;
}

sgx_status_t SGXDecentEnclave::TransitToDecentNode(const std::string & id)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;

	enclaveRet = ecall_transit_to_decent_node(GetEnclaveId(), &retval, id.c_str());
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

sgx_status_t SGXDecentEnclave::GetProtocolEncrKey(const std::string & id, sgx_ec256_private_t & outPriKey, sgx_aes_gcm_128bit_tag_t & outPriKeyMac, sgx_ec256_public_t & outPubKey, sgx_aes_gcm_128bit_tag_t & outPubKeyMac)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;

	enclaveRet = ecall_get_protocol_encr_key(GetEnclaveId(), &retval, id.c_str(), &outPriKey, &outPriKeyMac, &outPubKey, &outPubKeyMac);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_get_protocol_encr_key);

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

sgx_status_t SGXDecentEnclave::SetProtocolEncrKey(const std::string & id, const sgx_ec256_private_t & inPriKey, const sgx_aes_gcm_128bit_tag_t & inPriKeyMac, const sgx_ec256_public_t & inPubKey, const sgx_aes_gcm_128bit_tag_t & inPubKeyMac)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;

	enclaveRet = ecall_set_protocol_encr_key(GetEnclaveId(), &retval, id.c_str(), &inPriKey, &inPriKeyMac, &inPubKey, &inPubKeyMac);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_set_protocol_encr_key);

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

void SGXDecentEnclave::GetKeySigns(sgx_ec256_signature_t & outSignSign, sgx_ec256_signature_t & outEncrSign)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;

	enclaveRet = ecall_get_key_signs(GetEnclaveId(), &outSignSign, &outEncrSign);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_get_key_signs);
}

sgx_status_t SGXDecentEnclave::ProcessDecentMsg0(const std::string & id, const sgx_ec256_public_t & inSignKey, const sgx_ec256_signature_t & inSignSign, const sgx_ec256_public_t & inEncrKey, const sgx_ec256_signature_t & inEncrSign)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;

	enclaveRet = ecall_proc_decent_msg0(GetEnclaveId(), &retval, id.c_str(), &inSignKey, &inSignSign, &inEncrKey, &inEncrSign);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_proc_decent_msg0);

	return retval;
}
