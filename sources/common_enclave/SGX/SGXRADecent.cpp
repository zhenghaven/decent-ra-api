#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL

#include "SGXRADecent.h"

#include <string>
#include <map>
#include <memory>
#include <mutex>

#include <openssl/ec.h>

#include <sgx_utils.h>

#include <rapidjson/document.h>

#include <Enclave_t.h>

#include "../common_enclave/DecentError.h"

#include "../common/JsonTools.h"
#include "../common/CommonTool.h"
#include "../common/DataCoding.h"
#include "../common/OpenSSLTools.h"
#include "../common/DecentRAReport.h"
#include "../common/AESGCMCommLayer.h"
#include "../common/EnclaveAsyKeyContainer.h"

#include "../common/SGX/sgx_constants.h"
#include "../common/SGX/sgx_crypto_tools.h"
#include "../common/SGX/SGXRAServiceProvider.h"
#include "../common/SGX/SGXOpenSSLConversions.h"

#include "sgx_ra_tools.h"
#include "SGXRAClient.h"

typedef std::map<std::string, std::shared_ptr<const SecureCommLayer> > DecentNodeMapType;

namespace
{
	static constexpr char gsk_LabelFunc[] = "Func";
	static constexpr char gsk_LabelPrvKey[] = "PrvKey";

	static constexpr char gsk_ValueFuncSetProtoKey[] = "SetProtoKey";

	static std::mutex g_decentNodesMapMutex;
	static DecentNodeMapType g_decentNodesMap;
	static const DecentNodeMapType& k_decentNodesMap = g_decentNodesMap;

	static std::mutex g_pendingDecentNodeMutex;
	static std::map<std::string, std::string> g_pendingDecentNode;
}

static bool CommLayerSendFunc(void* const connectionPtr, const char* senderID, const char *msg)
{
	int retVal = 0;
	sgx_status_t enclaveRet = ocall_decent_send_trusted_msg(&retVal, connectionPtr, senderID, msg);
	if (enclaveRet != SGX_SUCCESS)
	{
		return false;
	}
	return retVal == 1;
}

static inline bool DecentReportDataVerifier(const std::string& pubSignKey, const uint8_t* initData, const std::vector<uint8_t>& inData)
{
	if (pubSignKey.size() == 0)
	{
		return false;
	}

	sgx_sha_state_handle_t shaState;
	sgx_sha256_hash_t tmpHash;
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
	enclaveRet = sgx_sha256_update(reinterpret_cast<const uint8_t*>(pubSignKey.data()), static_cast<uint32_t>(pubSignKey.size()), shaState);
	if (enclaveRet != SGX_SUCCESS)
	{
		sgx_sha256_close(shaState);
		return false;
	}
	enclaveRet = sgx_sha256_get_hash(shaState, &tmpHash);
	if (enclaveRet != SGX_SUCCESS)
	{
		sgx_sha256_close(shaState);
		return false;
	}
	sgx_sha256_close(shaState);

	return std::memcmp(tmpHash, inData.data(), sizeof(sgx_sha256_hash_t)) == 0;
}

static std::shared_ptr<const SecureCommLayer> FetchCommLayer(const std::string& nodeID)
{
	std::shared_ptr<const SecureCommLayer> commLayer;
	{
		std::lock_guard<std::mutex> mapLock(g_decentNodesMapMutex);
		auto it = g_decentNodesMap.find(nodeID);
		if (it == g_decentNodesMap.end())
		{
			return nullptr;
		}
		commLayer = it->second;
	}
	return commLayer;
}

void DecentEnclave::DropDecentNode(const std::string & nodeID)
{
	std::lock_guard<std::mutex> mapLock(g_decentNodesMapMutex);
	auto it = g_decentNodesMap.find(nodeID);
	if (it != g_decentNodesMap.end())
	{
		g_decentNodesMap.erase(it);
	}
}

bool DecentEnclave::IsAttested(const std::string& id)
{
	std::lock_guard<std::mutex> mapLock(g_decentNodesMapMutex);
	return k_decentNodesMap.find(id) != k_decentNodesMap.cend();
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
	SGXRAEnclave::SetTargetEnclaveHash(SerializeStruct(enclaveHash));

	return SGX_SUCCESS;
}

extern "C" void ecall_decent_terminate()
{

}

extern "C" int ecall_decent_process_ias_ra_report(const char* reportStr)
{
	if (!reportStr)
	{
		return 0;
	}
	rapidjson::Document jsonDoc;
	jsonDoc.Parse(reportStr);

	if (!jsonDoc.HasMember(Decent::RAReport::sk_LabelRoot))
	{
		return 0;
	}
	rapidjson::Value& jsonRoot = jsonDoc[Decent::RAReport::sk_LabelRoot];

	if (!jsonRoot.HasMember(Decent::RAReport::sk_LabelType) || !(std::string(jsonRoot[Decent::RAReport::sk_LabelType].GetString()) == Decent::RAReport::sk_ValueReportType))
	{
		return 0;
	}

	std::string selfHash = SGXRAEnclave::GetSelfHash();
	std::string pubKey = jsonRoot[Decent::RAReport::sk_LabelPubKey].GetString();
	std::string iasReport = jsonRoot[Decent::RAReport::sk_LabelIasReport].GetString();
	std::string iasSign = jsonRoot[Decent::RAReport::sk_LabelIasSign].GetString();
	std::string iasCertChain = jsonRoot[Decent::RAReport::sk_LabelIasCertChain].GetString();
	std::string oriRDB64 = jsonRoot[Decent::RAReport::sk_LabelOriRepData].GetString();
	sgx_report_data_t oriReportData;
	DeserializeStruct(oriReportData, oriRDB64);

	ReportDataVerifier reportDataVerifier = [pubKey](const uint8_t* initData, const std::vector<uint8_t>& inData) -> bool
	{
		return DecentReportDataVerifier(pubKey, initData, inData);
	};

	ias_quote_status_t quoteStatus = ias_quote_status_t::IAS_QUOTE_SIGNATURE_INVALID;
	bool reportVerifyRes = SGXRAEnclave::VerifyIASReport(&quoteStatus, iasReport, iasCertChain, iasSign, selfHash, oriReportData, reportDataVerifier, nullptr);

	if (reportVerifyRes)
	{
		EC_KEY* pubECKey = ECKeyPubFromPEMStr(pubKey);
		if (!pubECKey)
		{
			return 0;
		}
		sgx_ec256_public_t sgxPubKey;
		if (!ECKeyPairOpenSSL2SGX(pubECKey, nullptr, &sgxPubKey, nullptr))
		{
			return 0;
		}
		std::lock_guard<std::mutex> mapLock(g_pendingDecentNodeMutex);
		g_pendingDecentNode[SerializePubKey(sgxPubKey)] = pubKey;
	}

	return reportVerifyRes ? 1 : 0;
}

extern "C" sgx_status_t ecall_process_ra_msg0_send_decent(const char* clientID)
{
	if (!clientID)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}
	//std::map<std::string, std::pair<ClientRAState, RAKeyManager>>& clientsMap = EnclaveState::GetInstance().GetClientsMap();
	sgx_ec256_public_t clientSignkey;
	DeserializePubKey(clientID, clientSignkey);
	if (!SGXRAEnclave::AddNewClientRAState(clientID, clientSignkey))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	ReportDataVerifier reportDataVerifier = [clientSignkey](const uint8_t* initData, const std::vector<uint8_t>& inData) -> bool
	{
		EC_KEY* pubKey = EC_KEY_new();
		if (!pubKey || !ECKeyPubSGX2OpenSSL(&clientSignkey, pubKey, nullptr))
		{
			EC_KEY_free(pubKey);
			return false;
		}
		std::string pubKeyPem = ECKeyPubGetPEMStr(pubKey);
		EC_KEY_free(pubKey);
		return DecentReportDataVerifier(pubKeyPem, initData, inData);
	};

	SGXRAEnclave::SetReportDataVerifier(clientID, reportDataVerifier); //Imposible to return false on this call.

	return SGX_SUCCESS;
}

extern "C" sgx_status_t ecall_process_ra_msg0_resp_decent(const char* ServerID, const sgx_ec256_public_t* inPubKey, int enablePSE, sgx_ra_context_t* outContextID)
{
	if (!ServerID || !inPubKey || !outContextID ||
		!SGXRAEnclave::AddNewServerRAState(ServerID, *inPubKey))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	ReportDataGenerator rdGenerator = [](const uint8_t* initData, std::vector<uint8_t>& outData, const size_t inLen) -> bool
	{
		EC_KEY* pubKey = EC_KEY_new();
		std::shared_ptr<const sgx_ec256_public_t> signPub = EnclaveAsyKeyContainer::GetInstance().GetSignPubKey();
		if (!pubKey || !ECKeyPubSGX2OpenSSL(signPub.get(), pubKey, nullptr))
		{
			EC_KEY_free(pubKey);
			return false;
		}
		std::string pubKeyPem = ECKeyPubGetPEMStr(pubKey);
		EC_KEY_free(pubKey);
		if (pubKeyPem.size() == 0)
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

	return enclave_init_decent_ra(inPubKey, enablePSE, rdGenerator, nullptr, outContextID); //Error return. (Error from SGX)
}

extern "C" int ecall_to_decent_node(const char* nodeID, int isServer)
{
	if (!nodeID)
	{
		return 0;
	}

	if (isServer)
	{
		if (SGXRAEnclave::IsClientAttested(nodeID))
		{
			AESGCMCommLayer* commLayer = nullptr;
			commLayer = SGXRAEnclave::ReleaseClientKeys(nodeID, &CommLayerSendFunc);
			if (!commLayer)
			{
				return 0;
			}
			{
				std::lock_guard<std::mutex> mapLock(g_decentNodesMapMutex);
				g_decentNodesMap.insert(std::make_pair(nodeID, std::shared_ptr<const AESGCMCommLayer>(commLayer)));
			}
			COMMON_PRINTF("Accepted New Decent Node: %s\n", nodeID);
			return 1;
		}
	}
	else
	{
		bool isInPending = false;
		{
			std::lock_guard<std::mutex> mapLock(g_pendingDecentNodeMutex);
			isInPending = (g_pendingDecentNode.find(nodeID) != g_pendingDecentNode.end());
		}
		if (SGXRAEnclave::IsAttestedToServer(nodeID) && isInPending)
		{
			AESGCMCommLayer* commLayer = nullptr;
			{
				std::lock_guard<std::mutex> mapLock(g_pendingDecentNodeMutex);
				g_pendingDecentNode.erase(g_pendingDecentNode.find(nodeID));
			}
			commLayer = SGXRAEnclave::ReleaseServerKeys(nodeID, &CommLayerSendFunc);
			if (!commLayer)
			{
				return 0;
			}
			{
				std::lock_guard<std::mutex> mapLock(g_decentNodesMapMutex);
				g_decentNodesMap.insert(std::make_pair(nodeID, std::shared_ptr<const AESGCMCommLayer>(commLayer)));
			}
			COMMON_PRINTF("Accepted New Decent Node: %s\n", nodeID);
			return 1;
		}
	}
	return 0;
}

extern "C" int ecall_proc_decent_trusted_msg(const char* nodeID, void* const connectionPtr, const char* jsonMsg)
{
	if (!nodeID || !connectionPtr || !jsonMsg)
	{
		return 0;
	}
	std::shared_ptr<const SecureCommLayer> commLayer = FetchCommLayer(nodeID);
	if (!commLayer)
	{
		return 0;
	}

	std::string plainMsg;
	commLayer->DecryptMsg(plainMsg, jsonMsg);

	JSON_EDITION::JSON_DOCUMENT_TYPE jsonRoot;
	if (!ParseStr2Json(jsonRoot, plainMsg))
	{
		return 0;
	}

	if (!jsonRoot.HasMember(gsk_LabelFunc) || !jsonRoot[gsk_LabelFunc].IsString())
	{
		return 0;
	}

	std::string funcType(jsonRoot[gsk_LabelFunc].GetString());

	if (funcType == gsk_ValueFuncSetProtoKey) //Set Protocol Key Function:
	{
		if (!jsonRoot.HasMember(gsk_LabelPrvKey) || !jsonRoot[gsk_LabelPrvKey].IsString())
		{
			return 0;
		}
		sgx_ec256_public_t pubKey;
		DeserializeStruct(pubKey, nodeID);
		PrivateKeyWrap prvKey;
		DeserializeStruct(prvKey.m_prvKey, jsonRoot[gsk_LabelPrvKey].GetString());
		std::shared_ptr<const sgx_ec256_public_t> pubKeyPtr = std::shared_ptr<const sgx_ec256_public_t>(new const sgx_ec256_public_t(pubKey));
		std::shared_ptr<const PrivateKeyWrap> prvKeyPtr = std::shared_ptr<const PrivateKeyWrap>(new const PrivateKeyWrap(prvKey));
		EnclaveAsyKeyContainer::GetInstance().UpdateSignKeyPair(prvKeyPtr, pubKeyPtr);

		DecentEnclave::DropDecentNode(nodeID); //Task done! End the session.
		return 0; //return 0 to terminate the connection.
	}

	return 0;
}

extern "C" int ecall_decent_send_protocol_key(const char* nodeID, void* const connectionPtr)
{
	if (!nodeID || !connectionPtr)
	{
		return 0;
	}

	std::shared_ptr<const SecureCommLayer> commLayer = FetchCommLayer(nodeID);
	if (!commLayer)
	{
		return 0;
	}

	JSON_EDITION::JSON_DOCUMENT_TYPE doc;
	rapidjson::Value jsonRoot;

	std::string prvKeyB64 = SerializeStruct(EnclaveAsyKeyContainer::GetInstance().GetSignPrvKey()->m_prvKey);

	JsonCommonSetString(doc, jsonRoot, gsk_LabelFunc, gsk_ValueFuncSetProtoKey);
	JsonCommonSetString(doc, jsonRoot, gsk_LabelPrvKey, prvKeyB64);

	return commLayer->SendMsg(connectionPtr, Json2StyleString(jsonRoot));
}

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL
