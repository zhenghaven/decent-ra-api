#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL

#include "SGXRADecent.h"

#include <string>
#include <map>
#include <memory>
#include <mutex>

#include <sgx_utils.h>

#include <rapidjson/document.h>

#include <Enclave_t.h>

#include "../DecentError.h"
#include "../Common.h"

#include "../common/JsonTools.h"
#include "../common/DataCoding.h"
#include "../common/DecentRAReport.h"
#include "../common/AESGCMCommLayer.h"
#include "../common/EnclaveAsyKeyContainer.h"

#include "../common/SGX/sgx_constants.h"
#include "../common/SGX/sgx_crypto_tools.h"
#include "../common/SGX/ias_report.h"
#include "../common/SGX/IasReport.h"
#include "../common/SGX/SGXRAServiceProvider.h"
#include "../common/SGX/SGXOpenSSLConversions.h"

#include "decent_ra_tools.h"
#include "decent_tkey_exchange.h"
#include "SGXRAClient.h"
#include "SGXDecentCommon.h"

namespace
{
	static constexpr char gsk_LabelFunc[] = "Func";
	static constexpr char gsk_LabelPrvKey[] = "PrvKey";

	static constexpr char gsk_ValueFuncSetProtoKey[] = "SetProtoKey";

	//Assume this is set correctly during init and no change afterwards.
	static std::shared_ptr<const std::string> g_selfHash = std::make_shared<const std::string>("");

	std::string g_decentProtoPubKey;
}

static inline void SetSelfEnclaveHash(const std::string & hashBase64)
{
#ifdef DECENT_THREAD_SAFETY_HIGH
	std::atomic_store(&g_targetHash, std::make_shared<const std::string>(hashBase64));
#else
	g_selfHash = std::make_shared<const std::string>(hashBase64);
#endif // DECENT_THREAD_SAFETY_HIGH
}

static inline const std::string GetSelfEnclaveHash()
{
#ifdef DECENT_THREAD_SAFETY_HIGH
	return *std::atomic_load(&g_targetHash);
#else
	return *g_selfHash;
#endif // DECENT_THREAD_SAFETY_HIGH
}

static bool CommLayerSendFunc(void* const connectionPtr, const char* senderID, const char *msg, const char* appAttach)
{
	int retVal = 0;
	sgx_status_t enclaveRet = ocall_decent_send_trusted_msg(&retVal, connectionPtr, senderID, msg, appAttach);
	if (enclaveRet != SGX_SUCCESS)
	{
		return false;
	}
	return retVal == 1;
}

extern "C" sgx_status_t ecall_decent_init(const sgx_spid_t* inSpid)
{
	if (!inSpid)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}
	SGXRAEnclave::SetSPID(*inSpid);

	sgx_report_t selfReport;
	sgx_status_t res = sgx_create_report(nullptr, nullptr, &selfReport);
	if (res != SGX_SUCCESS)
	{
		return res; //Error return. (Error from SGX)
	}

	sgx_measurement_t& enclaveHash = selfReport.body.mr_enclave;
	ocall_printf("Enclave Program Hash: %s\n", SerializeStruct(enclaveHash).c_str());
	SetSelfEnclaveHash(SerializeStruct(enclaveHash));

	return SGX_SUCCESS;
}

extern "C" void ecall_decent_terminate()
{

}

extern "C" sgx_status_t ecall_decent_become_root()
{
	std::shared_ptr<const sgx_ec256_public_t> signPub = EnclaveAsyKeyContainer::GetInstance()->GetSignPubKey();
	std::string selfId(SerializeStruct(*signPub));
	bool isClientAttested = SGXRAEnclave::IsClientAttested(selfId);
	bool isServerAttested = SGXRAEnclave::IsAttestedToServer(selfId);

	if (isClientAttested && isServerAttested)
	{
		g_decentProtoPubKey = selfId;
		SGXRAEnclave::DropClientRAState(selfId);
		SGXRAEnclave::DropRAStateToServer(selfId);
		return SGX_SUCCESS;
	}

	return SGX_ERROR_INVALID_PARAMETER;
}

extern "C" int ecall_decent_process_ias_ra_report(const char* reportStr)
{
	if (!reportStr || g_decentProtoPubKey.size() > 0)
	{
		return 0;
	}

	sgx_ec256_public_t decentPubKey;
	std::string decentPubKeyPem;
	sgx_ias_report_t iasReport;

	if (!DecentEnclave::ProcessIasRaReport(reportStr, GetSelfEnclaveHash(), decentPubKey, &decentPubKeyPem, iasReport))
	{
		return 0;
	}

	g_decentProtoPubKey = SerializeStruct(decentPubKey);

	COMMON_PRINTF("Accepted New Decent Node: %s\n", g_decentProtoPubKey.c_str());

	return 1;
}

extern "C" sgx_status_t ecall_process_ra_msg1_decent(const char* client_id, const sgx_ec256_public_t* in_key, const sgx_ra_msg1_t *in_msg1, sgx_ra_msg2_t *out_msg2)
{
	if (!client_id || !in_key || !in_msg1 || !out_msg2)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	sgx_status_t enclaveRet = SGXRAEnclave::ProcessRaMsg1(client_id, *in_key, *in_msg1, *out_msg2);
	if (enclaveRet != SGX_SUCCESS)
	{
		return enclaveRet;
	}

	sgx_ec256_public_t clientSignkey(*in_key);
	ReportDataVerifier reportDataVerifier = [clientSignkey](const uint8_t* initData, const std::vector<uint8_t>& inData) -> bool
	{
		std::string pubKeyPem;
		ECKeyPubSGX2Pem(clientSignkey, pubKeyPem);
		if (pubKeyPem.size() == 0)
		{
			return false;
		}
		return DecentEnclave::DecentReportDataVerifier(pubKeyPem, initData, inData);
	};

	SGXRAEnclave::SetReportDataVerifier(client_id, reportDataVerifier); //Imposible to return false on this call.

	return SGX_SUCCESS;
}

extern "C" sgx_status_t ecall_process_ra_msg0_resp_decent(const char* serverID, const sgx_ec256_public_t* inPubKey, int enablePSE, sgx_ra_context_t* outContextID)
{
	if (!serverID || !inPubKey || !outContextID)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	ReportDataGenerator rdGenerator = [](const uint8_t* initData, std::vector<uint8_t>& outData, const size_t inLen) -> bool
	{
		std::shared_ptr<const sgx_ec256_public_t> signPub = EnclaveAsyKeyContainer::GetInstance()->GetSignPubKey();
		std::string pubKeyPem;

		bool res = ECKeyPubSGX2Pem(*signPub, pubKeyPem);
		if (!res || pubKeyPem.size() == 0)
		{
			return false;
		}

		COMMON_PRINTF("Generating report data with Public Key:\n%s\n", pubKeyPem.c_str());
		sgx_sha_state_handle_t shaState;
		sgx_status_t enclaveRet = sgx_sha256_init(&shaState);
		if (enclaveRet != SGX_SUCCESS)
		{
			return false;
		}
		enclaveRet = sgx_sha256_update(initData, SGX_SHA256_HASH_SIZE / 2, shaState);
		if (enclaveRet != SGX_SUCCESS)
		{
			sgx_sha256_close(shaState);
			return false;
		}
		enclaveRet = sgx_sha256_update(reinterpret_cast<const uint8_t*>(pubKeyPem.data()), static_cast<uint32_t>(pubKeyPem.size()), shaState);
		if (enclaveRet != SGX_SUCCESS)
		{
			sgx_sha256_close(shaState);
			return false;
		}
		outData.resize(SGX_SHA256_HASH_SIZE, 0);
		enclaveRet = sgx_sha256_get_hash(shaState, reinterpret_cast<sgx_sha256_hash_t*>(outData.data()));
		if (enclaveRet != SGX_SUCCESS)
		{
			sgx_sha256_close(shaState);
			return false;
		}
		sgx_sha256_close(shaState);

		return true;
	};

	sgx_status_t enclaveRet = enclave_init_decent_ra(inPubKey, enablePSE, rdGenerator, nullptr, outContextID);
	if (enclaveRet != SGX_SUCCESS)
	{
		return enclaveRet;
	}

	std::unique_ptr<CtxIdWrapper> sgxCtxId(new CtxIdWrapper(*outContextID, &decent_ra_close));
	bool res = SGXRAEnclave::AddNewServerRAState(serverID, *inPubKey, sgxCtxId);
	return res ? SGX_SUCCESS : SGX_ERROR_UNEXPECTED;
}

extern "C" sgx_status_t ecall_process_ra_msg4_decent(const char* serverID, const sgx_ias_report_t* inMsg4, const sgx_ec256_signature_t* inMsg4Sign)
{
	if (!serverID || !inMsg4 || !inMsg4Sign)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	return SGXRAEnclave::ProcessRaMsg4(serverID, *inMsg4, *inMsg4Sign, &decent_ra_get_keys);
}

//This function will be call at new node side.
extern "C" sgx_status_t ecall_proc_decent_proto_key_msg(const char* nodeID, void* const connectionPtr, const char* jsonMsg)
{
	if (!nodeID || !connectionPtr || !jsonMsg || g_decentProtoPubKey.size() == 0 || g_decentProtoPubKey != nodeID)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (!SGXRAEnclave::IsAttestedToServer(nodeID))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}
	AESGCMCommLayer* commLayer = SGXRAEnclave::ReleaseServerKeys(nodeID, &CommLayerSendFunc);
	if (!commLayer)
	{
		return SGX_ERROR_UNEXPECTED;
	}

	std::string plainMsg;
	if (!commLayer->DecryptMsg(plainMsg, jsonMsg))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	JSON_EDITION::JSON_DOCUMENT_TYPE jsonRoot;
	if (!ParseStr2Json(jsonRoot, plainMsg) || !jsonRoot.HasMember(gsk_LabelFunc) || !jsonRoot[gsk_LabelFunc].IsString())
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	std::string funcType(jsonRoot[gsk_LabelFunc].GetString());

	if (funcType == gsk_ValueFuncSetProtoKey && 
		jsonRoot.HasMember(gsk_LabelPrvKey) && jsonRoot[gsk_LabelPrvKey].IsString()) //Set Protocol Key Function:
	{
		sgx_ec256_public_t pubKey;
		DeserializeStruct(pubKey, nodeID);
		PrivateKeyWrap prvKey;
		DeserializeStruct(prvKey.m_prvKey, jsonRoot[gsk_LabelPrvKey].GetString());
		std::shared_ptr<const sgx_ec256_public_t> pubKeyPtr = std::shared_ptr<const sgx_ec256_public_t>(new const sgx_ec256_public_t(pubKey));
		std::shared_ptr<const PrivateKeyWrap> prvKeyPtr = std::shared_ptr<const PrivateKeyWrap>(new const PrivateKeyWrap(prvKey));
		EnclaveAsyKeyContainer::GetInstance()->UpdateSignKeyPair(prvKeyPtr, pubKeyPtr);

		return SGX_SUCCESS;
	}

	return SGX_ERROR_INVALID_PARAMETER;
}

//This function will be call at existing node side.
extern "C" sgx_status_t ecall_decent_send_protocol_key(const char* nodeID, void* const connectionPtr, const char* appAttach)
{
	if (!nodeID || !connectionPtr || g_decentProtoPubKey.size() == 0)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (!SGXRAEnclave::IsClientAttested(nodeID))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}
	std::unique_ptr<sgx_ias_report_t> iasReport;
	AESGCMCommLayer* commLayer = SGXRAEnclave::ReleaseClientKeys(nodeID, &CommLayerSendFunc, iasReport);
	if (!commLayer || !iasReport)
	{
		return SGX_ERROR_UNEXPECTED;
	}
	if (iasReport->m_status != static_cast<uint8_t>(ias_quote_status_t::IAS_QUOTE_OK))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}
	sgx_measurement_t targetHash;
	DeserializeStruct(targetHash, GetSelfEnclaveHash());
	if (!consttime_memequal(&iasReport->m_quote.report_body.mr_enclave, &targetHash, sizeof(sgx_measurement_t)))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	COMMON_PRINTF("Accepted New Decent Node: %s\n", nodeID);

	JSON_EDITION::JSON_DOCUMENT_TYPE doc;
	rapidjson::Value jsonRoot;

	std::string prvKeyB64 = SerializeStruct(EnclaveAsyKeyContainer::GetInstance()->GetSignPrvKey()->m_prvKey);

	JsonCommonSetString(doc, jsonRoot, gsk_LabelFunc, gsk_ValueFuncSetProtoKey);
	JsonCommonSetString(doc, jsonRoot, gsk_LabelPrvKey, prvKeyB64);

	return commLayer->SendMsg(connectionPtr, Json2StyleString(jsonRoot), appAttach) ? SGX_SUCCESS : SGX_ERROR_UNEXPECTED;
}

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL
