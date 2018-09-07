#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_APP_INTERNAL

#include <string>
#include <memory>
#include <cstring>

#include <sgx_report.h>
#include <sgx_error.h>
#include <sgx_ecp_types.h>
#include <sgx_dh.h>
#include <sgx_tcrypto.h>

#include <rapidjson/document.h>

#include <Enclave_t.h>

#include "SGXLA.h"
#include "SGXLADecent.h"
#include "SGXDecentCommon.h"

#include "../Common.h"
#include "../../common/DataCoding.h"
#include "../../common/JsonTools.h"
#include "../../common/SGX/SGXOpenSSLConversions.h"
#include "../../common/AESGCMCommLayer.h"
#include "../../common/EnclaveAsyKeyContainer.h"
#include "../../common/DecentRAReport.h"

#include "../../common/SGX/SGXRAServiceProvider.h"

namespace
{
	//Secure comm layer to decent server. (We only attest to one decent server once)
	static std::shared_ptr<const SecureCommLayer> g_decentCommLayer;

	//Hardcoded decent enclave's hash. (Not used until decent program is stable)
	static constexpr char gk_decentHash[] = "";

	static std::shared_ptr<const sgx_ec256_public_t> g_decentPubKey;
}

static bool CommLayerSendFunc(void* const connectionPtr, const char* senderID, const char *msg, const char* attach)
{
	int retVal = 0;
	sgx_status_t enclaveRet = ocall_decent_la_send_trusted_msg(&retVal, connectionPtr, senderID, msg, attach);
	if (enclaveRet != SGX_SUCCESS)
	{
		return false;
	}
	return retVal == 1;
}

extern "C" sgx_status_t ecall_decent_app_process_ias_ra_report(const char* reportStr)
{
	if (!reportStr)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	std::shared_ptr<sgx_ec256_public_t> decentPubKey = std::make_shared<sgx_ec256_public_t>();

	sgx_ias_report_t iasReport;
	bool verifyRes = DecentEnclave::ProcessIasRaReport(reportStr, gk_decentHash, *decentPubKey, nullptr, iasReport);
	//Won't be successful now, since the decent hash is unknown.
	//if (!verifyRes)
	//{
	//	return SGX_ERROR_INVALID_PARAMETER;
	//}

	g_decentPubKey = decentPubKey;
	//COMMON_PRINTF("Accepted Decent Server %s.\n", SerializeStruct(*g_decentPubKey).c_str());

	return SGX_SUCCESS;
}

extern "C" sgx_status_t ecall_decent_app_send_report_data(const char* decentId, void* const connectionPtr, const char* const appAttach)
{
	if (!decentId || !connectionPtr)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	std::unique_ptr<sgx_dh_session_enclave_identity_t> identity;
	std::unique_ptr<GeneralAES128BitKey> aesKey;
	if (!SGXLAEnclave::ReleasePeerKey(decentId, identity, aesKey) || !identity || !aesKey)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	//=============== Not used now 
	//sgx_measurement_t targetHash;
	//DeserializeStruct(targetHash, gk_decentHash);
	//const sgx_measurement_t& testHash = identity->mr_enclave;

	//if (!consttime_memequal(&targetHash, &testHash, sizeof(sgx_measurement_t)))
	//{
	//	return SGX_ERROR_INVALID_PARAMETER;
	//}
	//===============

	std::shared_ptr<EnclaveAsyKeyContainer> keyContainer = EnclaveAsyKeyContainer::GetInstance();
	std::shared_ptr<const sgx_ec256_public_t> pubKey = keyContainer->GetSignPubKey();
	std::shared_ptr<const SecureCommLayer> commLayer(new AESGCMCommLayer(*aesKey, SerializeStruct(*pubKey), &CommLayerSendFunc));

	sgx_report_data_t reportData;
	std::memset(&reportData, 0, sizeof(sgx_report_data_t));

	//std::shared_ptr<const std::string> pubPem = EnclaveAsyKeyContainer::GetInstance().GetSignPubPem();
	std::string pubPem;
	ECKeyPubSGX2Pem(*keyContainer->GetSignPubKey(), pubPem);

	sgx_sha_state_handle_t shaState;
	//sgx_sha256_hash_t tmpHash;
	sgx_status_t enclaveRet = sgx_sha256_init(&shaState);
	if (enclaveRet != SGX_SUCCESS)
	{
		return enclaveRet;
	}
	enclaveRet = sgx_sha256_update(reinterpret_cast<const uint8_t*>(pubPem.data()), static_cast<uint32_t>(pubPem.size()), shaState);
	if (enclaveRet != SGX_SUCCESS)
	{
		sgx_sha256_close(shaState);
		return enclaveRet;
	}
	enclaveRet = sgx_sha256_get_hash(shaState, reinterpret_cast<sgx_sha256_hash_t*>(&reportData));
	sgx_sha256_close(shaState);
	if (enclaveRet != SGX_SUCCESS)
	{
		return enclaveRet;
	}

	//std::memcpy(&reportData, &tmpHash, sizeof(sgx_sha256_hash_t));

	rapidjson::Document doc;
	rapidjson::Value jsonRoot;

	std::string reportDataB64 = SerializeStruct(reportData);

	JsonCommonSetString(doc, jsonRoot, SGXLADecent::gsk_LabelFunc, SGXLADecent::gsk_ValueFuncReportData);
	JsonCommonSetString(doc, jsonRoot, SGXLADecent::gsk_LabelReportData, reportDataB64);

	if (!commLayer->SendMsg(connectionPtr, Json2StyleString(jsonRoot), appAttach))
	{
		return SGX_ERROR_UNEXPECTED;
	}

	g_decentCommLayer = commLayer;

	return SGX_SUCCESS;
}

extern "C" sgx_status_t ecall_decent_app_proc_app_sign_msg(const char* jsonMsg, sgx_report_body_t* outReport, sgx_ec256_signature_t* outSign)
{
	if (!g_decentCommLayer || !g_decentPubKey)
	{
		return SGX_ERROR_UNEXPECTED;
	}

	std::shared_ptr<const SecureCommLayer> commLayer = g_decentCommLayer;
	g_decentCommLayer.reset();

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

	if (funcType == SGXLADecent::gsk_ValueFuncAppSign)
	{
		if (!jsonRoot.HasMember(SGXLADecent::gsk_LabelReport) || !jsonRoot[SGXLADecent::gsk_LabelReport].IsString() ||
		!jsonRoot.HasMember(SGXLADecent::gsk_LabelSign) || !jsonRoot[SGXLADecent::gsk_LabelSign].IsString() )
		{
			return SGX_ERROR_INVALID_PARAMETER;
		}

		DeserializeStruct(*outReport, jsonRoot[SGXLADecent::gsk_LabelReport].GetString());
		DeserializeStruct(*outSign, jsonRoot[SGXLADecent::gsk_LabelSign].GetString());

		sgx_ecc_state_handle_t ecState;
		sgx_status_t enclaveRet = SGX_SUCCESS;

		enclaveRet = sgx_ecc256_open_context(&ecState);
		if (enclaveRet != SGX_SUCCESS)
		{
			return enclaveRet;
		}

		uint8_t ecdsaRes = SGX_EC_INVALID_SIGNATURE;
		enclaveRet = sgx_ecdsa_verify(reinterpret_cast<uint8_t*>(outReport), sizeof(sgx_report_body_t), g_decentPubKey.get(), outSign, &ecdsaRes, ecState);
		sgx_ecc256_close_context(ecState);

		if (enclaveRet != SGX_SUCCESS)
		{
			return enclaveRet;
		}
		if (ecdsaRes != SGX_EC_VALID)
		{
			return SGX_ERROR_UNEXPECTED;
		}

		return SGX_SUCCESS;
	}

	return SGX_ERROR_INVALID_PARAMETER;
}

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_APP_INTERNAL
