#include "../../common/ModuleConfigInternal.h"

#if USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL

#include "SGXDecentEnclave.h"

#include <thread>

#include <sgx_ukey_exchange.h>

#include <json/json.h>

#include <openssl/ec.h>

#include <Enclave_u.h>

#include "../common/DataCoding.h"
#include "../common/SGX/SGXCryptoConversions.h"
#include "../common/DecentRAReport.h"

#include "../DecentMessages/DecentMessage.h"
#include "../DecentMessages/DecentAppMessage.h"
#include "../DecentRASession.h"
#include "../DecentAppLASession.h"

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

bool SGXDecentEnclave::ProcessDecentProtoKeyMsg(const std::string & nodeID, Connection& connection)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;

	enclaveRet = ecall_proc_decent_proto_key_msg(GetEnclaveId(), &retval, nodeID.c_str(), &connection);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_proc_decent_proto_key_msg);

	return retval == SGX_SUCCESS;
}

bool SGXDecentEnclave::SendProtocolKey(const std::string & nodeID, Connection& connection)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;

	enclaveRet = ecall_decent_send_protocol_key(GetEnclaveId(), &retval, nodeID.c_str(), &connection);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_decent_send_protocol_key);

	return retval == SGX_SUCCESS;
}

bool SGXDecentEnclave::ProcessAppX509Req(const std::string & appId, Connection& connection)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;

	enclaveRet = ecall_decent_proc_app_x509_req(GetEnclaveId(), &retval, appId.c_str(), &connection);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_decent_proc_app_x509_req);

	return retval == SGX_SUCCESS;
}

bool SGXDecentEnclave::ProcessSmartMessage(const std::string & category, const Json::Value & jsonMsg, Connection& connection)
{
	if (category == DecentMessage::sk_ValueCat)
	{
		return DecentRASession::SmartMsgEntryPoint(connection, *this, *this, jsonMsg);
	}
	else if (category == DecentAppMessage::sk_ValueCat)
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
	sgx_status_t retval = SGX_SUCCESS;
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

	bool webRet = m_ias->GetRevocationList(msg1.gid, sigRL);
	if (!webRet)
	{
		throw SGXEnclaveRuntimeException(SGX_ERROR_UNEXPECTED, "ias->GetRevocationList");
	}
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

	webRet = m_ias->GetQuoteReport(msg3Ref, msg3.size(), iasNonce, false, iasReport, reportSign, reportCertChain);
	if (!webRet)
	{
		throw SGXEnclaveRuntimeException(SGX_ERROR_UNEXPECTED, "ias->GetQuoteReport");
	}

	enclaveRet = ProcessRAMsg3(senderID, msg3, iasReport, reportSign, reportCertChain, msg4, msg4Sign, &oriReportData);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, SGXDecentEnclave::ProcessRAMsg3);
	enclaveRet = ProcessRAMsg4(senderID, msg4, msg4Sign);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, SGXDecentEnclave::ProcessRAMsg4);

	Json::Value root;
	Json::Value& decentReportBody = root[Decent::RAReport::sk_LabelRoot];
	decentReportBody[Decent::RAReport::sk_LabelIasReport] = iasReport;
	decentReportBody[Decent::RAReport::sk_LabelIasSign] = reportSign;
	decentReportBody[Decent::RAReport::sk_LabelIasCertChain] = reportCertChain;
	decentReportBody[Decent::RAReport::sk_LabelOriRepData] = SerializeStruct(oriReportData);

	enclaveRet = ecall_decent_server_generate_x509(GetEnclaveId(), &retval, m_ias.get(), GetEnclaveId());
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_decent_server_generate_x509);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(retval, ecall_decent_server_generate_x509);

	size_t certLen = 0;
	std::string retReport(5000, '\0');

	enclaveRet = ecall_decent_server_get_x509_pem(GetEnclaveId(), &certLen, &retReport[0], retReport.size());
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_decent_server_get_x509_pem);

	if (certLen > retReport.size())
	{
		retReport.resize(certLen);

		enclaveRet = ecall_decent_server_get_x509_pem(GetEnclaveId(), &certLen, &retReport[0], retReport.size());
		CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_decent_server_get_x509_pem);
	}

	retReport.resize(certLen);

	return retReport;
}

extern "C" int ocall_decent_ra_get_msg1(const uint64_t enclave_id, const uint32_t ra_ctx, sgx_ra_msg1_t* msg1)
{
	if (!msg1)
	{
		return false;
	}

	sgx_status_t enclaveRet = SGX_SUCCESS;
	std::thread tmpThread([&enclaveRet, enclave_id, ra_ctx, msg1]() {
		enclaveRet = sgx_ra_get_msg1(ra_ctx, enclave_id, decent_ra_get_ga, msg1);
	});
	tmpThread.join();

	return (enclaveRet == SGX_SUCCESS);
}

extern "C" size_t ocall_decent_ra_proc_msg2(const uint64_t enclave_id, const uint32_t ra_ctx, const sgx_ra_msg2_t* msg2, const size_t msg2_size, uint8_t** out_msg3)
{
	if (!msg2 || !out_msg3)
	{
		return 0;
	}

	*out_msg3 = nullptr;

	sgx_ra_msg3_t* tmpMsg3 = nullptr;
	uint32_t tmpMsg3Size = 0;
	sgx_status_t enclaveRet = SGX_SUCCESS;
	std::thread tmpThread([&enclaveRet, enclave_id, ra_ctx, msg2, msg2_size, &tmpMsg3, &tmpMsg3Size]() {
		enclaveRet = sgx_ra_proc_msg2(ra_ctx, enclave_id, decent_ra_proc_msg2_trusted, decent_ra_get_msg3_trusted,
			msg2, static_cast<uint32_t>(msg2_size), &tmpMsg3, &tmpMsg3Size);
	});
	tmpThread.join();

	if (enclaveRet != SGX_SUCCESS)
	{
		return 0;
	}

	//Copy msg3 to our buffer pointer to avoid the mix use of malloc and delete[];
	*out_msg3 = new uint8_t[tmpMsg3Size];
	std::memcpy(*out_msg3, tmpMsg3, tmpMsg3Size);
	std::free(tmpMsg3);

	return tmpMsg3Size;
}

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL
