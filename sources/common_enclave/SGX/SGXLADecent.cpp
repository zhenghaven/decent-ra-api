#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL

#include "SGXLADecent.h"

#define STRUCT_ASSERT_ERROR_MSG "Check sgx_report_body_t and sgx_dh_session_enclave_identity_t has different struct"

#include <string>
#include <memory>
#include <cstring>
#include <cstddef>

#include <sgx_report.h>
#include <sgx_error.h>
#include <sgx_ecp_types.h>
#include <sgx_dh.h>
#include <sgx_tcrypto.h>

#include <rapidjson/document.h>

#include <Enclave_t.h>

#include "SGXLA.h"

#include "../../common/DataCoding.h"
#include "../../common/JsonTools.h"
#include "../../common/AESGCMCommLayer.h"
#include "../../common/EnclaveAsyKeyContainer.h"

static bool CommLayerSendFunc(void* const connectionPtr, const char* senderID, const char *msg, const char* appAttach)
{
	int retVal = 0;
	sgx_status_t enclaveRet = ocall_decent_la_send_trusted_msg(&retVal, connectionPtr, senderID, msg, appAttach);
	if (enclaveRet != SGX_SUCCESS)
	{
		return false;
	}
	return retVal == 1;
}

static_assert(sizeof(sgx_report_body_t::cpu_svn) == sizeof(sgx_dh_session_enclave_identity_t::cpu_svn), STRUCT_ASSERT_ERROR_MSG);
static_assert(sizeof(sgx_report_body_t::misc_select) == sizeof(sgx_dh_session_enclave_identity_t::misc_select), STRUCT_ASSERT_ERROR_MSG);
static_assert(sizeof(sgx_report_body_t::reserved1) == sizeof(sgx_dh_session_enclave_identity_t::reserved_1), STRUCT_ASSERT_ERROR_MSG);
static_assert(sizeof(sgx_report_body_t::attributes) == sizeof(sgx_dh_session_enclave_identity_t::attributes), STRUCT_ASSERT_ERROR_MSG);
static_assert(sizeof(sgx_report_body_t::mr_enclave) == sizeof(sgx_dh_session_enclave_identity_t::mr_enclave), STRUCT_ASSERT_ERROR_MSG);
static_assert(sizeof(sgx_report_body_t::reserved2) == sizeof(sgx_dh_session_enclave_identity_t::reserved_2), STRUCT_ASSERT_ERROR_MSG);
static_assert(sizeof(sgx_report_body_t::mr_signer) == sizeof(sgx_dh_session_enclave_identity_t::mr_signer), STRUCT_ASSERT_ERROR_MSG);
static_assert(sizeof(sgx_report_body_t::reserved3) == sizeof(sgx_dh_session_enclave_identity_t::reserved_3), STRUCT_ASSERT_ERROR_MSG);
static_assert(sizeof(sgx_report_body_t::isv_prod_id) == sizeof(sgx_dh_session_enclave_identity_t::isv_prod_id), STRUCT_ASSERT_ERROR_MSG);
static_assert(sizeof(sgx_report_body_t::isv_svn) == sizeof(sgx_dh_session_enclave_identity_t::isv_svn), STRUCT_ASSERT_ERROR_MSG);

static_assert(offsetof(sgx_report_body_t, cpu_svn) == offsetof(sgx_dh_session_enclave_identity_t, cpu_svn), STRUCT_ASSERT_ERROR_MSG);
static_assert(offsetof(sgx_report_body_t, misc_select) == offsetof(sgx_dh_session_enclave_identity_t, misc_select), STRUCT_ASSERT_ERROR_MSG);
static_assert(offsetof(sgx_report_body_t, reserved1) == offsetof(sgx_dh_session_enclave_identity_t, reserved_1), STRUCT_ASSERT_ERROR_MSG);
static_assert(offsetof(sgx_report_body_t, attributes) == offsetof(sgx_dh_session_enclave_identity_t, attributes), STRUCT_ASSERT_ERROR_MSG);
static_assert(offsetof(sgx_report_body_t, mr_enclave) == offsetof(sgx_dh_session_enclave_identity_t, mr_enclave), STRUCT_ASSERT_ERROR_MSG);
static_assert(offsetof(sgx_report_body_t, reserved2) == offsetof(sgx_dh_session_enclave_identity_t, reserved_2), STRUCT_ASSERT_ERROR_MSG);
static_assert(offsetof(sgx_report_body_t, mr_signer) == offsetof(sgx_dh_session_enclave_identity_t, mr_signer), STRUCT_ASSERT_ERROR_MSG);
static_assert(offsetof(sgx_report_body_t, reserved3) == offsetof(sgx_dh_session_enclave_identity_t, reserved_3), STRUCT_ASSERT_ERROR_MSG);
static_assert(offsetof(sgx_report_body_t, isv_prod_id) == offsetof(sgx_dh_session_enclave_identity_t, isv_prod_id), STRUCT_ASSERT_ERROR_MSG);
static_assert(offsetof(sgx_report_body_t, isv_svn) == offsetof(sgx_dh_session_enclave_identity_t, isv_svn), STRUCT_ASSERT_ERROR_MSG);
static_assert(offsetof(sgx_report_body_t, reserved4) == sizeof(sgx_dh_session_enclave_identity_t), STRUCT_ASSERT_ERROR_MSG);

static inline sgx_status_t ecall_decent_send_app_report_sign(const sgx_dh_session_enclave_identity_t& identity, const sgx_report_data_t& reportData, std::unique_ptr<const SecureCommLayer>& commLayer, void* const connectionPtr, const char* appAttach)
{
	sgx_report_body_t report = { 0 };

	//If we can sure the structure of sgx_dh_session_enclave_identity_t and sgx_report_body_t are similar, we can do a faster copy.
	std::memcpy(&(report.cpu_svn), &(identity.cpu_svn), sizeof(sgx_dh_session_enclave_identity_t));
	std::memcpy(&(report.report_data), &reportData, sizeof(sgx_report_data_t));

	std::shared_ptr<const PrivateKeyWrap> signKey = EnclaveAsyKeyContainer::GetInstance()->GetSignPrvKey();
	sgx_status_t enclaveRet = SGX_SUCCESS;
	sgx_ec256_signature_t signature;
	sgx_ecc_state_handle_t ecState;

	enclaveRet = sgx_ecc256_open_context(&ecState);
	if (enclaveRet != SGX_SUCCESS)
	{
		return enclaveRet;
	}

	enclaveRet = sgx_ecdsa_sign(reinterpret_cast<uint8_t*>(&report), sizeof(report), const_cast<sgx_ec256_private_t*>(&signKey->m_prvKey), &signature, ecState);
	if (enclaveRet != SGX_SUCCESS)
	{
		return enclaveRet;
	}

	sgx_ecc256_close_context(ecState);

	rapidjson::Document doc;
	rapidjson::Value jsonRoot;

	std::string reportB64 = SerializeStruct(report);
	std::string signB64 = SerializeStruct(signature);

	JsonCommonSetString(doc, jsonRoot, SGXLADecent::gsk_LabelFunc, SGXLADecent::gsk_ValueFuncAppSign);
	JsonCommonSetString(doc, jsonRoot, SGXLADecent::gsk_LabelReport, reportB64);
	JsonCommonSetString(doc, jsonRoot, SGXLADecent::gsk_LabelSign, signB64);

	if (!commLayer->SendMsg(connectionPtr, Json2StyleString(jsonRoot), appAttach))
	{
		return SGX_ERROR_UNEXPECTED;
	}

	return SGX_SUCCESS;
}


extern "C" sgx_status_t ecall_decent_proc_send_app_sign_req(const char* peerId, void* const connectionPtr, const char* jsonMsg, const char* appAttach)
{
	if (!peerId || !connectionPtr || !jsonMsg)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	sgx_dh_session_enclave_identity_t identity;
	sgx_ec_key_128bit_t aesKey;
	if (!SGXLAEnclave::ReleasePeerKey(peerId, identity, aesKey))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	std::shared_ptr<const sgx_ec256_public_t> pubKey = EnclaveAsyKeyContainer::GetInstance()->GetSignPubKey();
	std::unique_ptr<const SecureCommLayer> commLayer(new AESGCMCommLayer(aesKey, SerializeStruct(*pubKey), &CommLayerSendFunc));

	std::string plainMsg;
	if (!commLayer->DecryptMsg(plainMsg, jsonMsg))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	JSON_EDITION::JSON_DOCUMENT_TYPE jsonRoot;
	if (!ParseStr2Json(jsonRoot, plainMsg) ||
		!jsonRoot.HasMember(SGXLADecent::gsk_LabelFunc) ||
		!jsonRoot[SGXLADecent::gsk_LabelFunc].IsString())
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	std::string funcType(jsonRoot[SGXLADecent::gsk_LabelFunc].GetString());

	if (funcType == SGXLADecent::gsk_ValueFuncReportData)
	{
		if (!jsonRoot.HasMember(SGXLADecent::gsk_LabelReportData) || !jsonRoot[SGXLADecent::gsk_LabelReportData].IsString())
		{
			return SGX_ERROR_INVALID_PARAMETER;
		}

		sgx_report_data_t reportData;
		DeserializeStruct(reportData, jsonRoot[SGXLADecent::gsk_LabelReportData].GetString());

		return ecall_decent_send_app_report_sign(identity, reportData, commLayer, connectionPtr, appAttach);
	}

	return SGX_ERROR_INVALID_PARAMETER;
}

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL
