#include "SGXDecentEnclave.h"

#include <iostream>

#include <sgx_ukey_exchange.h>

#include <json/json.h>

#include <openssl/ec.h>

#include <Enclave_u.h>

#include "../common/DataCoding.h"
#include "../common/OpenSSLTools.h"
#include "../common/SGX/sgx_ra_msg4.h"
#include "../common/SGX/SGXOpenSSLConversions.h"
#include "../common/DecentRAReport.h"

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

sgx_status_t SGXDecentEnclave::ProcessRAMsg2(const std::string & ServerID, const std::vector<uint8_t>& inMsg2, std::vector<uint8_t>& outMsg3, sgx_ra_context_t & inContextID)
{
	return SGXEnclave::ProcessRAMsg2(ServerID, inMsg2, outMsg3, inContextID, decent_ra_proc_msg2_trusted, decent_ra_get_msg3_trusted);
}

sgx_status_t SGXDecentEnclave::ProcessRAMsg3(const std::string & clientID, const std::vector<uint8_t> & inMsg3, const std::string & iasReport, const std::string & reportSign, const std::string& reportCertChain, sgx_ra_msg4_t & outMsg4, sgx_ec256_signature_t & outMsg4Sign, sgx_report_data_t* outOriRD)
{
	sgx_status_t retval = SGXEnclaveServiceProvider::ProcessRAMsg3(clientID, inMsg3, iasReport, reportSign, reportCertChain, outMsg4, outMsg4Sign, outOriRD);
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

bool SGXDecentEnclave::CreateDecentSelfRAReport(std::string & outReport)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;
	sgx_ec256_public_t pubKey;
	GetRAClientSignPubKey(pubKey);
	std::string senderID = SerializeStruct(pubKey);

	sgx_ra_context_t raCtx;
	sgx_ra_msg1_t msg1;
	std::vector<uint8_t> msg2;
	std::string sigRL;
	std::vector<uint8_t> msg3;
	sgx_ra_msg4_t msg4;
	sgx_ec256_signature_t msg4Sign;
	sgx_report_data_t oriReportData;

	std::string iasNonce;
	std::string iasReport;
	std::string reportSign;
	std::string reportCertChain;

	enclaveRet = ProcessRAMsg0Send(senderID);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, SGXDecentEnclave::ProcessRAMsg0Send);
	enclaveRet = ProcessRAMsg0Resp(senderID, pubKey, false, raCtx, msg1);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, SGXDecentEnclave::ProcessRAMsg0Resp);

	/*TODO: Safety check here: */
	int16_t webRet = m_ias.GetRevocationList(msg1.gid, sigRL);
	std::vector<uint8_t> sigRLData;
	DeserializeStruct(sigRLData, sigRL);
	msg2.resize(sizeof(sgx_ra_msg2_t) + sigRLData.size());
	sgx_ra_msg2_t& msg2Ref = *reinterpret_cast<sgx_ra_msg2_t*>(msg2.data());

	enclaveRet = ProcessRAMsg1(senderID, msg1, msg2Ref);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, SGXDecentEnclave::ProcessRAMsg1);

	msg2Ref.sig_rl_size = static_cast<uint32_t>(sigRLData.size());
	std::memcpy(msg2.data() + sizeof(sgx_ra_msg2_t), sigRLData.data(), sigRLData.size());
	
	enclaveRet = ProcessRAMsg2(senderID, msg2, msg3, raCtx);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, SGXDecentEnclave::ProcessRAMsg2);
	enclaveRet = GetIasReportNonce(senderID, iasNonce);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, SGXDecentEnclave::GetIasReportNonce);

	sgx_ra_msg3_t& msg3Ref = *reinterpret_cast<sgx_ra_msg3_t*>(msg3.data());
	Json::Value iasReqRoot;
	iasReqRoot["isvEnclaveQuote"] = static_cast<std::string>(SerializeStruct(msg3Ref.quote, msg3.size() - sizeof(sgx_ra_msg3_t)));
	iasReqRoot["nonce"] = iasNonce;
	/*TODO: Safety check here: */
	webRet = m_ias.GetQuoteReport(iasReqRoot.toStyledString(), iasReport, reportSign, reportCertChain);

	enclaveRet = ProcessRAMsg3(senderID, msg3, iasReport, reportSign, reportCertChain, msg4, msg4Sign, &oriReportData);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, SGXDecentEnclave::ProcessRAMsg3);
	enclaveRet = ProcessRAMsg4(senderID, msg4, msg4Sign, raCtx);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, SGXDecentEnclave::ProcessRAMsg4);

	/*TODO: Safety check here: */
	EC_KEY* pubECKey = EC_KEY_new();
	bool opensslRet = ECKeyPubSGX2OpenSSL(&pubKey, pubECKey, nullptr);

	Json::Value root;
	Json::Value& decentReportBody = root[Decent::RAReport::LABEL_ROOT];
	decentReportBody[Decent::RAReport::LABEL_TYPE] = Decent::RAReport::VALUE_REPORT_TYPE;
	decentReportBody[Decent::RAReport::LABEL_PUB_KEY] = ECKeyPubGetPEMStr(pubECKey);
	decentReportBody[Decent::RAReport::LABEL_IAS_REPORT] = iasReport;
	decentReportBody[Decent::RAReport::LABEL_IAS_SIGN] = reportSign;
	decentReportBody[Decent::RAReport::LABEL_IAS_CERT_CHAIN] = reportCertChain;
	decentReportBody[Decent::RAReport::LABEL_ORI_REP_DATA] = SerializeStruct(oriReportData);

	outReport = root.toStyledString();
	return true;
}

bool SGXDecentEnclave::ProcessDecentSelfRAReport(const std::string & inReport)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;
	int retval = SGX_SUCCESS;

	enclaveRet = ecall_decent_process_ias_ra_report(GetEnclaveId(), &retval, inReport.c_str());
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_process_ias_ra_report);

	return retval != 0;
}

bool SGXDecentEnclave::ProcessDecentTrustedMsg(const std::string & nodeID, const std::unique_ptr<Connection>& connection, const std::string & jsonMsg)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;
	int retval = SGX_SUCCESS;

	enclaveRet = ecall_proc_decent_trusted_msg(GetEnclaveId(), &retval, nodeID.c_str(), connection.get(), jsonMsg.c_str());
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_proc_decent_trusted_msg);

	return retval != 0;
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
