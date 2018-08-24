#include "SGXRADecent.h"

#include <string>
#include <map>
#include <memory>

#include <openssl/ec.h>

#include <sgx_utils.h>

#include <rapidjson/document.h>

#include "../common_enclave/DecentError.h"

#include "../common/Decent.h"
#include "../common/CommonTool.h"
#include "../common/DataCoding.h"
#include "../common/OpenSSLTools.h"
#include "../common/EnclaveRAState.h"
#include "../common/DecentRAReport.h"
#include "../common/EnclaveAsyKeyContainer.h"
#include "../common/SGX/sgx_constants.h"
#include "../common/SGX/sgx_crypto_tools.h"
#include "../common/SGX/SGXRAServiceProvider.h"
#include "../common/SGX/SGXOpenSSLConversions.h"

#include "sgx_ra_tools.h"
#include "SGXRAClient.h"

class Connection;

struct DecentNodeContext
{
	sgx_ec256_public_t m_peerSignKey = { {0},{0} };
	sgx_ec_key_128bit_t m_mk = { 0 };
	sgx_ec_key_128bit_t m_sk = { 0 };

};

namespace
{
	static DecentNodeMode g_decentMode = DecentNodeMode::ROOT_SERVER;
	static std::map<std::string, DecentNodeContext> g_decentNodesMap;
	static std::map<std::string, std::string> g_pendingDecentNode;

	//Shared objects:
	//static std::shared_ptr<DecentCryptoManager> g_cryptoMgr = std::make_shared<DecentCryptoManager>();
}

static bool IsBothWayAttested(const std::string& id)
{
	bool isClientAttested = SGXRAEnclave::IsClientAttested(id);
	bool isServerAttested = SGXRAEnclave::IsServerAttested(id);

	return isClientAttested && isServerAttested;
}

static inline bool DecentReportDataVerifier(const std::string& pubSignKey, const uint8_t* initData, const std::vector<uint8_t>& inData)
{
	if (pubSignKey.size() == 0)
	{
		return false;
	}

	//COMMON_PRINTF("Verifying report data with Public Key:\n%s\n", pubSignKey.c_str());
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

bool DecentEnclave::IsAttested(const std::string& id)
{
	return g_decentNodesMap.find(id) != g_decentNodesMap.end();
}

extern "C" sgx_status_t ecall_decent_init(const sgx_spid_t* inSpid)
{
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
	std::shared_ptr<const sgx_ec256_public_t> signPub = EnclaveAsyKeyContainer::GetInstance().GetSignPubKey();
	ocall_printf("Enclave Public Sign key: %s\n", SerializeStruct(*signPub).c_str());

	return SGX_SUCCESS;
}

extern "C" void ecall_decent_terminate()
{

}

extern "C" int ecall_decent_process_ias_ra_report(const char* reportStr)
{
	rapidjson::Document jsonDoc;
	jsonDoc.Parse(reportStr);

	if (!jsonDoc.HasMember(Decent::RAReport::LABEL_ROOT))
	{
		return 0;
	}
	rapidjson::Value& jsonRoot = jsonDoc[Decent::RAReport::LABEL_ROOT];

	if (!jsonRoot.HasMember(Decent::RAReport::LABEL_TYPE) || !(std::string(jsonRoot[Decent::RAReport::LABEL_TYPE].GetString()) == Decent::RAReport::VALUE_REPORT_TYPE))
	{
		return 0;
	}

	std::string selfHash = SGXRAEnclave::GetSelfHash();
	std::string pubKey = jsonRoot[Decent::RAReport::LABEL_PUB_KEY].GetString();
	std::string iasReport = jsonRoot[Decent::RAReport::LABEL_IAS_REPORT].GetString();
	std::string iasSign = jsonRoot[Decent::RAReport::LABEL_IAS_SIGN].GetString();
	std::string iasCertChain = jsonRoot[Decent::RAReport::LABEL_IAS_CERT_CHAIN].GetString();
	std::string oriRDB64 = jsonRoot[Decent::RAReport::LABEL_ORI_REP_DATA].GetString();
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

extern "C" int ecall_proc_decent_trusted_msg(const char* nodeID, void* const connectionPtr, const char* jsonMsg)
{

	return true;
}

extern "C" int ecall_to_decentralized_node(const char* id, int is_server)
{
	if (!IsBothWayAttested(id))
	{
		return 0;
	}

	if (is_server)
	{
		auto it = g_decentNodesMap.insert(std::make_pair(id, DecentNodeContext()));
		SGXRAEnclave::GetClientKeys(id, &it.first->second.m_peerSignKey, &it.first->second.m_sk, &it.first->second.m_mk);
		SGXRAEnclave::DropServerRAState(id);
	}
	else
	{
		auto it = g_decentNodesMap.insert(std::make_pair(id, DecentNodeContext()));
		SGXRAEnclave::GetServerKeys(id, &it.first->second.m_peerSignKey, &it.first->second.m_sk, &it.first->second.m_mk);
		SGXRAEnclave::DropClientRAState(id);
	}

	COMMON_PRINTF("Accepted New Decentralized Node: %s\n", id);

	return 1;
}
