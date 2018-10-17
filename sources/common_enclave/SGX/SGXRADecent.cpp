#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL

#include <string>
#include <map>
#include <memory>
#include <mutex>

#include <sgx_utils.h>

#include <rapidjson/document.h>

#include <Enclave_t.h>

#include "../DecentError.h"
#include "../Common.h"
#include "../DecentCrypto.h"

#include "../../common/JsonTools.h"
#include "../../common/DataCoding.h"
#include "../../common/DecentCrypto.h"
#include "../../common/DecentRAReport.h"
#include "../../common/AESGCMCommLayer.h"
#include "../../common/CryptoKeyContainer.h"

#include "../../common/SGX/sgx_constants.h"
#include "../../common/SGX/ias_report.h"
#include "../../common/SGX/IasReport.h"
#include "../../common/SGX/SGXRAServiceProvider.h"
#include "../../common/SGX/SGXCryptoConversions.h"

#include "../../common/DecentCertContainer.h"
#include "../../common/DecentRAReport.h"

#include "decent_ra_tools.h"
#include "decent_tkey_exchange.h"
#include "SGXRAClient.h"

extern "C" sgx_status_t ecall_decent_init(const sgx_spid_t* inSpid)
{
	if (!inSpid)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}
	SGXRAEnclave::SetSPID(*inSpid);

	std::string selfHash = Decent::Crypto::GetProgSelfHashBase64();

	ocall_printf("Enclave Program Hash: %s\n", selfHash.c_str());

	return SGX_SUCCESS;
}

extern "C" void ecall_decent_terminate()
{

}

extern "C" sgx_status_t ecall_decent_server_generate_x509(const char* selfReport)
{
	std::shared_ptr<const general_secp256r1_public_t> signPub = CryptoKeyContainer::GetInstance().GetSignPubKey();
	std::shared_ptr<const MbedTlsObj::ECKeyPair> signkeyPair = CryptoKeyContainer::GetInstance().GetSignKeyPair();

	std::string selfId(SerializeStruct(*signPub));
	bool isClientAttested = SGXRAEnclave::IsClientAttested(selfId);
	bool isServerAttested = SGXRAEnclave::IsAttestedToServer(selfId);

	if (isClientAttested && isServerAttested)
	{
		//g_decentProtoPubKey = selfId;
		std::shared_ptr<const Decent::ServerX509> serverCert(new Decent::ServerX509(*signkeyPair, 
			Decent::Crypto::GetProgSelfHashBase64(), Decent::RAReport::sk_ValueReportTypeSgx, selfReport));
		if (!serverCert)
		{
			return SGX_ERROR_UNEXPECTED;
		}
		//DecentCertContainer::Get().SetCert(serverCert);
		DecentCertContainer::Get().SetServerCert(serverCert);

		SGXRAEnclave::DropClientRAState(selfId);
		SGXRAEnclave::DropRAStateToServer(selfId);
		return SGX_SUCCESS;
	}

	return SGX_ERROR_INVALID_PARAMETER;
}

extern "C" size_t ecall_decent_server_get_x509_pem(char* buf, size_t buf_len)
{
	auto serverCert = DecentCertContainer::Get().GetServerCert();
	if (!serverCert || !(*serverCert))
	{
		return 0;
	}

	std::string x509Pem = serverCert->ToPemString();
	std::memcpy(buf, x509Pem.data(), buf_len > x509Pem.size() ? x509Pem.size() : buf_len);

	return x509Pem.size();
}

extern "C" int ecall_decent_process_ias_ra_report(const char* x509Pem)
{
	auto serverCert = DecentCertContainer::Get().GetServerCert();

	if (!x509Pem || serverCert)
	{
		return 0;
	}

	std::shared_ptr<Decent::ServerX509> inCert(new Decent::ServerX509(x509Pem));
	if (!inCert || !(*inCert))
	{
		return 0;
	}

	sgx_ias_report_t iasReport;

	if (!Decent::RAReport::ProcessSelfRaReport(inCert->GetPlatformType(), inCert->GetEcPublicKey().ToPubPemString(),
		inCert->GetSelfRaReport(), Decent::Crypto::GetProgSelfHashBase64(), iasReport))
	{
		return 0;
	}
	DecentCertContainer::Get().SetServerCert(inCert);
	//COMMON_PRINTF("Accepted New Decent Node: %s\n", g_decentProtoPubKey.c_str());

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
		MbedTlsObj::ECKeyPublic pubKey(SgxEc256Type2General(clientSignkey));
		std::string pubKeyPem = pubKey.ToPubPemString();
		if (pubKeyPem.size() == 0)
		{
			return false;
		}
		return Decent::RAReport::DecentReportDataVerifier(pubKeyPem, initData, inData);
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
		std::shared_ptr<const MbedTlsObj::ECKeyPublic> signPub = CryptoKeyContainer::GetInstance().GetSignKeyPair();

		std::string pubKeyPem = signPub->ToPubPemString();
		if (pubKeyPem.size() == 0)
		{
			return false;
		}

		//COMMON_PRINTF("Generating report data with Public Key:\n%s\n", pubKeyPem.c_str());
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
extern "C" sgx_status_t ecall_proc_decent_proto_key_msg(const char* nodeID, void* const connectionPtr)
{
	auto serverCert = DecentCertContainer::Get().GetServerCert();

	if (!nodeID || !connectionPtr || 
		!serverCert ||
		!(*serverCert) ||
		!SGXRAEnclave::IsAttestedToServer(nodeID))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	std::unique_ptr<AESGCMCommLayer> commLayer(SGXRAEnclave::ReleaseServerKeys(nodeID));
	if (!commLayer)
	{
		return SGX_ERROR_UNEXPECTED;
	}

	std::string plainMsg;
	if (!commLayer->ReceiveMsg(connectionPtr, plainMsg))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	std::shared_ptr<const MbedTlsObj::ECKeyPair> protoKeyPair(new MbedTlsObj::ECKeyPair(plainMsg));
	if (!protoKeyPair || !*protoKeyPair ||
		!CryptoKeyContainer::GetInstance().UpdateSignKeyPair(protoKeyPair))
	{
		return SGX_ERROR_UNEXPECTED;
	}

	//DecentCertContainer::Get().SetCert(serverCert);

	COMMON_PRINTF("Joined Decent network.\n");

	return SGX_SUCCESS;
}

//This function will be call at existing node side.
extern "C" sgx_status_t ecall_decent_send_protocol_key(const char* nodeID, void* const connectionPtr)
{
	auto serverCert = DecentCertContainer::Get().GetServerCert();

	if (!nodeID || !connectionPtr ||
		!serverCert ||
		!(*serverCert))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	if (!SGXRAEnclave::IsClientAttested(nodeID))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}
	std::unique_ptr<sgx_ias_report_t> iasReport;
	std::unique_ptr<AESGCMCommLayer> commLayer(SGXRAEnclave::ReleaseClientKeys(nodeID, iasReport));

	if (!commLayer || !iasReport)
	{
		return SGX_ERROR_UNEXPECTED;
	}
	if (iasReport->m_status != static_cast<uint8_t>(ias_quote_status_t::IAS_QUOTE_OK))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	const General256Hash& targetHash = Decent::Crypto::GetGetProgSelfHash256();
	
	if (!consttime_memequal(iasReport->m_quote.report_body.mr_enclave.m, targetHash.data(), sizeof(sgx_measurement_t)))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	COMMON_PRINTF("Accepted New Decent Node: %s\n", nodeID);

	return commLayer->SendMsg(connectionPtr, CryptoKeyContainer::GetInstance().GetSignKeyPair()->ToPrvPemString()) ?
		SGX_SUCCESS : SGX_ERROR_UNEXPECTED;
}

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL
