#include "../../common/ModuleConfigInternal.h"

#if USE_INTEL_SGX_ENCLAVE_INTERNAL && (USE_DECENT_ENCLAVE_SERVER_INTERNAL || USE_DECENT_ENCLAVE_APP_INTERNAL)

#include "../DecentMessages/DecentAppMessage.h"
#include "../Networking/Connection.h"

#endif // USE_INTEL_SGX_ENCLAVE_INTERNAL && (USE_DECENT_ENCLAVE_SERVER_INTERNAL || USE_DECENT_ENCLAVE_APP_INTERNAL)

#if USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL

#include "SGXDecentEnclave.h"

#include <iostream>

#include <sgx_ukey_exchange.h>

#include <json/json.h>

#include <openssl/ec.h>

#include <Enclave_u.h>

#include "../common/DataCoding.h"
#include "../common/OpenSSLTools.h"
#include "../common/SGX/SGXOpenSSLConversions.h"
#include "../common/SGX/ias_report.h"
#include "../common/DecentRAReport.h"

#include "../DecentMessages/DecentMessage.h"
#include "../DecentRASession.h"
#include "../DecentAppLASession.h"

#include "SGXMessages/SGXLAMessage.h"
#include "IAS/IASConnector.h"
#include "SGXEnclaveRuntimeException.h"

static void InitDecent(sgx_enclave_id_t id, const sgx_spid_t& spid)
{
	sgx_status_t retval = SGX_SUCCESS;
	sgx_status_t enclaveRet = ecall_decent_init(id, &retval, &spid);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_decent_init);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(retval, ecall_decent_init);
}

SGXDecentEnclave::SGXDecentEnclave(const sgx_spid_t& spid, const std::shared_ptr<IASConnector>& ias, const bool isFirstNode, const std::string& enclavePath, const std::string& tokenPath) :
	SGXEnclaveServiceProvider(ias, enclavePath, tokenPath)
{
	InitDecent(GetEnclaveId(), spid);
	if (isFirstNode)
	{
		m_selfRaReport = GenerateDecentSelfRAReport();
	}
}

SGXDecentEnclave::SGXDecentEnclave(const sgx_spid_t& spid, const std::shared_ptr<IASConnector>& ias, const bool isFirstNode, const fs::path& enclavePath, const fs::path& tokenPath) :
	SGXEnclaveServiceProvider(ias, enclavePath, tokenPath)
{
	InitDecent(GetEnclaveId(), spid);
	if (isFirstNode)
	{
		m_selfRaReport = GenerateDecentSelfRAReport();
	}
}

SGXDecentEnclave::SGXDecentEnclave(const sgx_spid_t& spid, const std::shared_ptr<IASConnector>& ias, const bool isFirstNode, const std::string& enclavePath, const KnownFolderType tokenLocType, const std::string& tokenFileName) :
	SGXEnclaveServiceProvider(ias, enclavePath, tokenLocType, tokenFileName)
{
	InitDecent(GetEnclaveId(), spid);
	if (isFirstNode)
	{
		m_selfRaReport = GenerateDecentSelfRAReport();
	}
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

sgx_status_t SGXDecentEnclave::ProcessRAMsg1(const std::string & clientID, const sgx_ec256_public_t & inKey, const sgx_ra_msg1_t & inMsg1, sgx_ra_msg2_t & outMsg2)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;
	enclaveRet = ecall_process_ra_msg1_decent(GetEnclaveId(), &retval, clientID.c_str(), &inKey, &inMsg1, &outMsg2);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_process_ra_msg1_decent);

	return retval;
}

sgx_status_t SGXDecentEnclave::ProcessRAMsg2(const std::string & ServerID, const std::vector<uint8_t>& inMsg2, std::vector<uint8_t>& outMsg3, sgx_ra_context_t & inContextID)
{
	return SGXEnclave::ProcessRAMsg2(ServerID, inMsg2, outMsg3, inContextID, decent_ra_proc_msg2_trusted, decent_ra_get_msg3_trusted);
}

sgx_status_t SGXDecentEnclave::ProcessRAMsg4(const std::string & ServerID, const sgx_ias_report_t & inMsg4, const sgx_ec256_signature_t & inMsg4Sign)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;

	enclaveRet = ecall_process_ra_msg4_decent(GetEnclaveId(), &retval, ServerID.c_str(), &inMsg4, &inMsg4Sign);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_process_ra_msg4_decent);

	return retval;
}

std::string SGXDecentEnclave::GetDecentSelfRAReport() const
{
	return m_selfRaReport;
}

bool SGXDecentEnclave::ProcessDecentSelfRAReport(const std::string & inReport)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;
	int retval = SGX_SUCCESS;

	enclaveRet = ecall_decent_process_ias_ra_report(GetEnclaveId(), &retval, inReport.c_str());
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_decent_process_ias_ra_report);

	return retval != 0;
}

bool SGXDecentEnclave::DecentBecomeRoot()
{
	sgx_status_t enclaveRet = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;

	enclaveRet = ecall_decent_become_root(GetEnclaveId(), &retval);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_decent_become_root);

	return retval == SGX_SUCCESS;
}

bool SGXDecentEnclave::ProcessDecentProtoKeyMsg(const std::string & nodeID, Connection& connection, const std::string & jsonMsg)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;

	enclaveRet = ecall_proc_decent_proto_key_msg(GetEnclaveId(), &retval, nodeID.c_str(), &connection, jsonMsg.c_str());
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_proc_decent_proto_key_msg);

	return retval == SGX_SUCCESS;
}

bool SGXDecentEnclave::SendProtocolKey(const std::string & nodeID, Connection& connection)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;

	enclaveRet = ecall_decent_send_protocol_key(GetEnclaveId(), &retval, nodeID.c_str(), &connection, nullptr);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_decent_send_protocol_key);

	return retval == SGX_SUCCESS;
}

bool SGXDecentEnclave::ProcessAppReportSignReq(const std::string & appId, Connection& connection, const std::string & jsonMsg, const char * appAttach)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;

	enclaveRet = ecall_decent_proc_send_app_sign_req(GetEnclaveId(), &retval, appId.c_str(), &connection, jsonMsg.c_str(), appAttach);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_decent_proc_send_app_sign_req);

	return retval == SGX_SUCCESS;
}

bool SGXDecentEnclave::ProcessSmartMessage(const std::string & category, const Json::Value & jsonMsg, Connection& connection)
{
	if (category == DecentMessage::sk_ValueCat)
	{
		return DecentRASession::SmartMsgEntryPoint(connection, *this, *this, jsonMsg);
	}
	else if (category == SGXLAMessage::sk_ValueCat)
	{
		return DecentServerLASession::SmartMsgEntryPoint(connection, *this, *this, jsonMsg);
	}
	else
	{
		return false;
	}
}

std::string SGXDecentEnclave::GenerateDecentSelfRAReport()
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
	sgx_ias_report_t msg4;
	sgx_ec256_signature_t msg4Sign;
	sgx_report_data_t oriReportData;

	std::string iasNonce;
	std::string iasReport;
	std::string reportSign;
	std::string reportCertChain;

	enclaveRet = ProcessRAMsg0Resp(senderID, pubKey, false, raCtx, msg1);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, SGXDecentEnclave::ProcessRAMsg0Resp);

	/*TODO: Safety check here: */
	int16_t webRet = m_ias->GetRevocationList(msg1.gid, sigRL);
	std::vector<uint8_t> sigRLData;
	DeserializeStruct(sigRLData, sigRL);
	msg2.resize(sizeof(sgx_ra_msg2_t) + sigRLData.size());
	sgx_ra_msg2_t& msg2Ref = *reinterpret_cast<sgx_ra_msg2_t*>(msg2.data());

	enclaveRet = ProcessRAMsg1(senderID, pubKey, msg1, msg2Ref);
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
	webRet = m_ias->GetQuoteReport(iasReqRoot.toStyledString(), iasReport, reportSign, reportCertChain);

	enclaveRet = ProcessRAMsg3(senderID, msg3, iasReport, reportSign, reportCertChain, msg4, msg4Sign, &oriReportData);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, SGXDecentEnclave::ProcessRAMsg3);
	enclaveRet = ProcessRAMsg4(senderID, msg4, msg4Sign);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, SGXDecentEnclave::ProcessRAMsg4);

	//ToDecentralizedNode(senderID, true);

	/*TODO: Safety check here: */
	EC_KEY* pubECKey = ECKeyGeneral2OpenSSL(SgxEc256Type2General(&pubKey), nullptr);

	Json::Value root;
	Json::Value& decentReportBody = root[Decent::RAReport::sk_LabelRoot];
	decentReportBody[Decent::RAReport::sk_LabelType] = Decent::RAReport::sk_ValueReportType;
	decentReportBody[Decent::RAReport::sk_LabelPubKey] = ECKeyPubGetPEMStr(pubECKey);
	decentReportBody[Decent::RAReport::sk_LabelIasReport] = iasReport;
	decentReportBody[Decent::RAReport::sk_LabelIasSign] = reportSign;
	decentReportBody[Decent::RAReport::sk_LabelIasCertChain] = reportCertChain;
	decentReportBody[Decent::RAReport::sk_LabelOriRepData] = SerializeStruct(oriReportData);

	return root.toStyledString();
}

extern "C" int ocall_decent_send_trusted_msg(void* connectionPtr, const char* senderID, const char *msg, const char* appAttach)
{
	if (!connectionPtr || !msg)
	{
		return 0;
	}

	DecentTrustedMessage trustedMsg(senderID, msg, appAttach ? appAttach : "");
	Connection* cnt = reinterpret_cast<Connection*>(connectionPtr);
	std::string sentMsg = trustedMsg.ToJsonString();
	size_t sentLen = cnt->Send(sentMsg);

	return (sentLen == sentMsg.size()) ? 1 : 0;
}

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL

#if USE_INTEL_SGX_ENCLAVE_INTERNAL && (USE_DECENT_ENCLAVE_SERVER_INTERNAL || USE_DECENT_ENCLAVE_APP_INTERNAL)

extern "C" int ocall_decent_la_send_trusted_msg(void* connectionPtr, const char* senderID, const char *msg, const char* appAttach)
{
	if (!connectionPtr || !msg)
	{
		return 0;
	}

	DecentAppTrustedMessage trustedMsg(senderID, msg, appAttach ? appAttach : "");
	Connection* cnt = reinterpret_cast<Connection*>(connectionPtr);
	std::string sentMsg = trustedMsg.ToJsonString();
	size_t sentLen = cnt->Send(sentMsg);

	return (sentLen == sentMsg.size()) ? 1 : 0;
}

#endif // USE_INTEL_SGX_ENCLAVE_INTERNAL && (USE_DECENT_ENCLAVE_SERVER_INTERNAL || USE_DECENT_ENCLAVE_APP_INTERNAL)
