#include "SGXRAServiceProvider.h"

#include <cstdlib>
#include <string>
#include <map>
#include <memory>
#include <atomic>

#include <openssl/x509.h>

#include <sgx_quote.h>
#include <sgx_key_exchange.h>

#include <rapidjson/document.h>

#include <cppcodec/base64_rfc4648.hpp>

#include "../../common/CommonTool.h"
#include "../../common/DataCoding.h"
#include "../../common/OpenSSLTools.h"
#include "../../common/NonceGenerator.h"
#include "../../common/EnclaveRAState.h"
#include "../../common/EnclaveAsyKeyContainer.h"
#include "../../common/SGX/ias_report_cert.h"
#include "../../common/SGX/sgx_crypto_tools.h"
#include "../../common/SGX/sgx_constants.h"
#include "../../common/SGX/sgx_ra_msg4.h"

struct RASPContext
{
	std::shared_ptr<const sgx_ec256_public_t> m_mySignPub;
	std::shared_ptr<const PrivateKeyWrap> m_mySignPrv;
	sgx_ec256_private_t m_prvKey;
	sgx_ec256_public_t m_pubKey;
	ClientRAState m_state;
	std::string m_nonce;
	ReportDataVerifier m_reportDataVerifier;
	sgx_ec256_public_t m_peerSignKey;
	sgx_ec256_public_t m_peerEncrKey;
	sgx_ec256_dh_shared_t m_sharedKey;
	sgx_ec_key_128bit_t m_smk = { 0 };
	sgx_ec_key_128bit_t m_mk = { 0 };
	sgx_ec_key_128bit_t m_sk = { 0 };
	sgx_ec_key_128bit_t m_vk = { 0 };
	sgx_ps_sec_prop_desc_t m_secProp;

	RASPContext(const sgx_ec256_public_t& inSignPubKey) :
		m_mySignPub(EnclaveAsyKeyContainer::GetInstance().GetSignPubKey()),
		m_mySignPrv(EnclaveAsyKeyContainer::GetInstance().GetSignPrvKey()),
		m_prvKey(),
		m_pubKey(),
		m_peerSignKey(inSignPubKey),
		m_peerEncrKey({ {0}, {0} }),
		m_sharedKey({ {0} }),
		m_secProp({ {0} }),
		m_state(ClientRAState::MSG0_DONE),
		m_nonce(GenNonceForIASJson(IAS_REQUEST_NONCE_SIZE))
	{
		m_reportDataVerifier = [](const uint8_t* initData, const std::vector<uint8_t>& inData) -> bool
		{
			return std::memcmp(initData, inData.data(), inData.size()) == 0;
		};
	}

	sgx_status_t SetEncrPubKey(const sgx_ec256_public_t& inEncrPubKey)
	{
		std::memcpy(&m_peerEncrKey, &inEncrPubKey, sizeof(sgx_ec256_public_t));

		sgx_ecc_state_handle_t ecState;
		sgx_status_t enclaveRet = sgx_ecc256_open_context(&ecState);
		if (enclaveRet != SGX_SUCCESS)
		{
			return enclaveRet;
		}
		enclaveRet = sgx_ecc256_compute_shared_dhkey(&m_prvKey, &m_peerEncrKey, &m_sharedKey, ecState);
		if (enclaveRet != SGX_SUCCESS)
		{
			return enclaveRet;
		}
		sgx_ecc256_close_context(ecState);

		enclaveRet = derive_key_set(&m_sharedKey, &m_smk, &m_mk, &m_sk, &m_vk);
		return enclaveRet;
	}
};

namespace
{
	//Assume this is set correctly during init and no change afterwards.
	static std::shared_ptr<const sgx_spid_t> g_sgxSPID = std::make_shared<const sgx_spid_t>();
	//Assume this is set correctly during init and no change afterwards.
	static std::shared_ptr<const std::string> g_selfHash = std::make_shared<const std::string>("");

	static std::map<std::string, std::unique_ptr<RASPContext>> g_clientsMap;
}

bool SGXRAEnclave::AddNewClientRAState(const std::string& clientID, const sgx_ec256_public_t& inPubKey)
{
	auto it = g_clientsMap.find(clientID);
	if (it != g_clientsMap.end())
	{
		//Error return. (Error caused by invalid input.)
		FUNC_ERR_Y("Processing msg0, but client ID already exist.", false);
	}

	std::unique_ptr<RASPContext> spCTX(new RASPContext(inPubKey));
	sgx_ecc_state_handle_t ecState;
	sgx_status_t enclaveRet = sgx_ecc256_open_context(&ecState);
	if (!spCTX || (enclaveRet != SGX_SUCCESS))
	{
		sgx_ecc256_close_context(ecState);
		return false;
	}
	enclaveRet = sgx_ecc256_create_key_pair(&spCTX->m_prvKey, &spCTX->m_pubKey, ecState);
	sgx_ecc256_close_context(ecState);
	if (enclaveRet != SGX_SUCCESS)
	{
		return false;
	}
	
	g_clientsMap.insert(std::make_pair<const std::string&, std::unique_ptr<RASPContext>>(clientID, std::move(spCTX)));
	spCTX.reset();
	return true;
}

bool SGXRAEnclave::SetReportDataVerifier(const std::string & clientID, ReportDataVerifier func)
{
	auto it = g_clientsMap.find(clientID);
	if (it == g_clientsMap.end())
	{
		return false;
	}

	it->second->m_reportDataVerifier = func;
	return true;
}

void SGXRAEnclave::DropClientRAState(const std::string & clientID)
{
	auto it = g_clientsMap.find(clientID);
	if (it != g_clientsMap.end())
	{
		g_clientsMap.erase(it);
	}
}

bool SGXRAEnclave::IsClientAttested(const std::string & clientID)
{
	auto it = g_clientsMap.find(clientID);
	return it == g_clientsMap.end() ? false : (it->second->m_state == ClientRAState::ATTESTED);
}

bool SGXRAEnclave::GetClientKeys(const std::string & clientID, sgx_ec256_public_t* outSignPubKey, sgx_ec_key_128bit_t * outSK, sgx_ec_key_128bit_t * outMK)
{
	if (!outSK && !outMK && !outSignPubKey)
	{
		return false;
	}
	auto it = g_clientsMap.find(clientID);
	if (it == g_clientsMap.end())
	{
		return false;
	}

	RASPContext& spCTX = *(it->second);

	if (outSK)
	{
		std::memcpy(outSK, &spCTX.m_sk, sizeof(sgx_ec_key_128bit_t));
	}
	if (outMK)
	{
		std::memcpy(outMK, &spCTX.m_mk, sizeof(sgx_ec_key_128bit_t));
	}
	if (outSignPubKey)
	{
		std::memcpy(outSignPubKey, &spCTX.m_peerSignKey, sizeof(sgx_ec256_public_t));
	}

	return true;
}

void SGXRAEnclave::SetTargetEnclaveHash(const std::string & hashBase64)
{
#ifdef DECENT_THREAD_SAFETY_HIGH
	std::atomic_store(&g_selfHash, std::make_shared<const std::string>(hashBase64));
#else
	g_selfHash = std::make_shared<const std::string>(hashBase64);
#endif // DECENT_THREAD_SAFETY_HIGH
}

void SGXRAEnclave::SetSPID(const sgx_spid_t & spid)
{
	std::shared_ptr<const sgx_spid_t> tmpSPID = std::make_shared<const sgx_spid_t>(spid);

#ifdef DECENT_THREAD_SAFETY_HIGH
	std::atomic_store(&g_sgxSPID, tmpSPID);
#else
	g_sgxSPID = tmpSPID;
#endif // DECENT_THREAD_SAFETY_HIGH
}

std::string SGXRAEnclave::GetSelfHash()
{
#ifdef DECENT_THREAD_SAFETY_HIGH
	return *std::atomic_load(&g_selfHash);
#else
	return *g_selfHash;
#endif // DECENT_THREAD_SAFETY_HIGH
}

sgx_status_t SGXRAEnclave::ServiceProviderInit()
{
	sgx_status_t res = SGX_SUCCESS;
	if (!EnclaveAsyKeyContainer::GetInstance().IsValid())
	{
		return SGX_ERROR_UNEXPECTED; //Error return. (Error from SGX)
	}

	std::shared_ptr<const sgx_ec256_public_t> signPub = EnclaveAsyKeyContainer::GetInstance().GetSignPubKey();
	COMMON_PRINTF("SP's public Sign Key: %s\n", SerializePubKey(*signPub).c_str());

	return SGX_SUCCESS;
}

void SGXRAEnclave::ServiceProviderTerminate()
{
}

sgx_status_t SGXRAEnclave::GetIasNonce(const char* clientID, char* outStr)
{
	if (!clientID)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}
	auto it = g_clientsMap.find(clientID);
	if (it == g_clientsMap.end())
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}
	const std::string& res = it->second->m_nonce;
	std::memcpy(outStr, res.data(), res.size());

	return SGX_SUCCESS;
}

sgx_status_t SGXRAEnclave::GetRASPSignPubKey(sgx_ec256_public_t * outKey)
{
	if (!outKey)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}
	if (!EnclaveAsyKeyContainer::GetInstance().IsValid())
	{
		return SGX_ERROR_UNEXPECTED; //Error return. (Error from SGX)
	}

	std::shared_ptr<const sgx_ec256_public_t> signPub = EnclaveAsyKeyContainer::GetInstance().GetSignPubKey();
	std::memcpy(outKey, signPub.get(), sizeof(sgx_ec256_public_t));
	return SGX_SUCCESS;
}

sgx_status_t SGXRAEnclave::ProcessRaMsg0Send(const char* clientID)
{
	if (!clientID)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	sgx_ec256_public_t clientSignkey;
	DeserializePubKey(clientID, clientSignkey);
	if (!AddNewClientRAState(clientID, clientSignkey))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	return SGX_SUCCESS;
}

sgx_status_t SGXRAEnclave::ProcessRaMsg1(const char* clientID, const sgx_ra_msg1_t *inMsg1, sgx_ra_msg2_t *outMsg2)
{
	auto it = g_clientsMap.find(clientID);
	if (it == g_clientsMap.end()
		|| it->second->m_state != ClientRAState::MSG0_DONE)
	{
		SGXRAEnclave::DropClientRAState(clientID);
		//Error return. (Error caused by invalid input.)
		FUNC_ERR("Processing msg1, but client ID doesn't exist or in a invalid state.");
	}

	RASPContext& spCTX = *(it->second);

	sgx_status_t res = SGX_SUCCESS;

	res = spCTX.SetEncrPubKey(inMsg1->g_a);
	if (res != SGX_SUCCESS)
	{
		SGXRAEnclave::DropClientRAState(clientID);
		return res; //Error return. (Error from SGX)
	}

	memcpy(&(outMsg2->g_b), &(spCTX.m_pubKey), sizeof(sgx_ec256_public_t));
#ifdef DECENT_THREAD_SAFETY_HIGH
	std::shared_ptr<const sgx_spid_t> tmpSPID = std::atomic_load(&g_sgxSPID);
#else
	std::shared_ptr<const sgx_spid_t> tmpSPID = g_sgxSPID;
#endif // DECENT_THREAD_SAFETY_HIGH
	memcpy(&(outMsg2->spid), tmpSPID.get(), sizeof(sgx_spid_t));
	outMsg2->quote_type = SGX_QUOTE_LINKABLE_SIGNATURE;

	outMsg2->kdf_id = SAMPLE_AES_CMAC_KDF_ID;

	sgx_ec256_public_t gb_ga[2];
	memcpy(&gb_ga[0], &(spCTX.m_pubKey), sizeof(sgx_ec256_public_t));
	memcpy(&gb_ga[1], &(spCTX.m_peerEncrKey), sizeof(sgx_ec256_public_t));

	{
		sgx_ecc_state_handle_t eccState;
		res = sgx_ecc256_open_context(&eccState);
		if (res != SGX_SUCCESS)
		{
			SGXRAEnclave::DropClientRAState(clientID);
			return res; //Error return. (Error from SGX)
		}
		res = sgx_ecdsa_sign((uint8_t *)&gb_ga, sizeof(gb_ga), const_cast<sgx_ec256_private_t*>(&(spCTX.m_mySignPrv->m_prvKey)), &(outMsg2->sign_gb_ga), eccState);
		if (res != SGX_SUCCESS)
		{
			SGXRAEnclave::DropClientRAState(clientID);
			return res; //Error return. (Error from SGX)
		}
		sgx_ecc256_close_context(eccState);
	}

	uint8_t mac[SAMPLE_EC_MAC_SIZE] = { 0 };
	uint32_t cmac_size = offsetof(sgx_ra_msg2_t, mac);
	res = sgx_rijndael128_cmac_msg(reinterpret_cast<sgx_cmac_128bit_key_t*>(&(spCTX.m_smk)), (uint8_t *)&(outMsg2->g_b), cmac_size, &mac);
	memcpy(&(outMsg2->mac), mac, sizeof(mac));

	outMsg2->sig_rl_size = 0;

	spCTX.m_state = ClientRAState::MSG1_DONE;

	return res; //Error return. (Error from SGX)
}

sgx_status_t SGXRAEnclave::ProcessRaMsg3(const char* clientID, const uint8_t* inMsg3, uint32_t msg3Len, const char* iasReport, const char* reportSign, const char* reportCert, sgx_ra_msg4_t* outMsg4, sgx_ec256_signature_t* outMsg4Sign, sgx_report_data_t* outOriRD)
{
	auto it = g_clientsMap.find(clientID);
	if (it == g_clientsMap.end()
		|| it->second->m_state != ClientRAState::MSG1_DONE)
	{
		SGXRAEnclave::DropClientRAState(clientID);
		//Error return. (Error caused by invalid input.)
		FUNC_ERR("Processing msg3, but client ID doesn't exist or in a invalid state.");
	}

	RASPContext& spCTX = *(it->second);

	sgx_status_t res = SGX_SUCCESS;
	int cmpRes = 0;
	const sgx_ra_msg3_t* msg3 = reinterpret_cast<const sgx_ra_msg3_t*>(inMsg3);

	// Compare g_a in message 3 with local g_a.
	cmpRes = std::memcmp(&(spCTX.m_peerEncrKey), &msg3->g_a, sizeof(sgx_ec256_public_t));
	if (cmpRes)
	{
		SGXRAEnclave::DropClientRAState(clientID);
		//Error return. (Error caused by invalid input.)
		FUNC_ERR("Processing msg3, g_a doesn't match!");
	}

	//Make sure that msg3_size is bigger than sgx_mac_t.
	uint32_t mac_size = msg3Len - sizeof(sgx_mac_t);
	const uint8_t *p_msg3_cmaced = inMsg3;
	p_msg3_cmaced += sizeof(sgx_mac_t);

	res = verify_cmac128(&(spCTX.m_smk), p_msg3_cmaced, mac_size, (msg3->mac));
	if (res != SGX_SUCCESS)
	{
		SGXRAEnclave::DropClientRAState(clientID);
		return res; //Error return. (Error from SGX)
	}

	std::memcpy(&spCTX.m_secProp, &msg3->ps_sec_prop, sizeof(sgx_ps_sec_prop_desc_t));

	//const sgx_quote_t* p_quote = reinterpret_cast<const sgx_quote_t *>(msg3->quote);

	sgx_sha_state_handle_t sha_handle = nullptr;
	sgx_report_data_t report_data = { 0 };
	// Verify the report_data in the Quote matches the expected value.
	// The first 32 bytes of report_data are SHA256 HASH of {ga|gb|vk}.
	// The second 32 bytes of report_data are set to zero.
	res = sgx_sha256_init(&sha_handle);
	if (res != SGX_SUCCESS)
	{
		SGXRAEnclave::DropClientRAState(clientID);
		return res; //Error return. (Error from SGX)
	}

	res = sgx_sha256_update(reinterpret_cast<const uint8_t*>(&(spCTX.m_peerEncrKey)), sizeof(sgx_ec256_public_t), sha_handle);
	if (res != SGX_SUCCESS)
	{
		SGXRAEnclave::DropClientRAState(clientID);
		return res;
	}

	res = sgx_sha256_update(reinterpret_cast<const uint8_t*>(&spCTX.m_pubKey), sizeof(sgx_ec256_public_t), sha_handle);
	if (res != SGX_SUCCESS)
	{
		SGXRAEnclave::DropClientRAState(clientID);
		return res; //Error return. (Error from SGX)
	}

	res = sgx_sha256_update(reinterpret_cast<const uint8_t*>(&(spCTX.m_vk)), sizeof(sgx_ec_key_128bit_t), sha_handle);
	if (res != SGX_SUCCESS)
	{
		SGXRAEnclave::DropClientRAState(clientID);
		return res; //Error return. (Error from SGX)
	}

	res = sgx_sha256_get_hash(sha_handle, (sgx_sha256_hash_t *)&report_data);
	if (res != SGX_SUCCESS)
	{
		SGXRAEnclave::DropClientRAState(clientID);
		return res; //Error return. (Error from SGX)
	}
	
	if (outOriRD)
	{
		std::memcpy(outOriRD, &report_data, sizeof(sgx_report_data_t));
	}

	bool iasVerifyRes = SGXRAEnclave::VerifyIASReport(&outMsg4->status, iasReport, reportCert, reportSign, SGXRAEnclave::GetSelfHash(), report_data, spCTX.m_reportDataVerifier, spCTX.m_nonce.c_str());
	if (!iasVerifyRes)
	{
		SGXRAEnclave::DropClientRAState(clientID);
		//Error return. (Error caused by invalid input.)
		FUNC_ERR("Processing msg3, IAS report got rejected!");
	}

	//TODO: Decide if we need to add PSE.
	outMsg4->pse_status = ias_pse_status_t::IAS_PSE_OK;

	{
		sgx_ecc_state_handle_t eccState;
		res = sgx_ecc256_open_context(&eccState);
		if (res != SGX_SUCCESS)
		{
			SGXRAEnclave::DropClientRAState(clientID);
			return res; //Error return. (Error from SGX)
		}
		res = sgx_ecdsa_sign((uint8_t *)outMsg4, sizeof(sgx_ra_msg4_t), const_cast<sgx_ec256_private_t*>(&(spCTX.m_mySignPrv->m_prvKey)), outMsg4Sign, eccState);
		if (res != SGX_SUCCESS)
		{
			SGXRAEnclave::DropClientRAState(clientID);
			return res; //Error return. (Error from SGX)
		}
		sgx_ecc256_close_context(eccState);
	}

	if (outMsg4->status == ias_quote_status_t::IAS_QUOTE_OK)
	{
		spCTX.m_state = ClientRAState::ATTESTED;
	}
	else
	{
		SGXRAEnclave::DropClientRAState(clientID);
		//Error return. (Error caused by invalid input.)
		FUNC_ERR("Processing msg3, quote got rejected by IAS!");
	}

	return SGX_SUCCESS;
}

bool SGXRAEnclave::VerifyIASReport(ias_quote_status_t* outStatus,const std::string& iasReport, const std::string& reportCert, const std::string& reportSign, const std::string& progHash, const sgx_report_data_t& oriRD, ReportDataVerifier rdVerifier, const char* nonce)
{
#ifndef SIMULATING_ENCLAVE
	std::vector<X509*> certs;
	LoadX509CertsFromStr(certs, IAS_REPORT_CERT);
	X509* iasCert = certs[0];

	LoadX509CertsFromStr(certs, reportCert);

	bool certVerRes = VerifyIasReportCert(iasCert, certs);

	std::vector<uint8_t> buffer1 = cppcodec::base64_rfc4648::decode<std::vector<uint8_t>, std::string>(reportSign);

	bool signVerRes = VerifyIasReportSignature(iasReport, buffer1, certs[0]);

	FreeX509Cert(&iasCert);
	FreeX509Cert(certs);

	COMMON_PRINTF("IAS Report Certs Verify Result:     %s \n", certVerRes ? "Success!" : "Failed!");
	COMMON_PRINTF("IAS Report Signature Verify Result: %s \n", signVerRes ? "Success!" : "Failed!");

	if (!certVerRes || !signVerRes)
	{
		return false;
	}
#else
	COMMON_PRINTF("IAS Report Certs Verify Result:     %s \n", "Simulated!");
	COMMON_PRINTF("IAS Report Signature Verify Result: %s \n", "Simulated!");
#endif // !SIMULATING_ENCLAVE

	rapidjson::Document jsonDoc;
	jsonDoc.Parse(iasReport.c_str());
	*outStatus = ParseIASQuoteStatus(jsonDoc["isvEnclaveQuoteStatus"].GetString());
	//COMMON_PRINTF("IAS Report Verify Result:           %s \n", quoteStatus == ias_quote_status_t::IAS_QUOTE_OK ? "Success!" : "Failed!");

	if (nonce)
	{
		bool isNonceMatch = (std::memcmp(jsonDoc["nonce"].GetString(), nonce, std::strlen(nonce)) == 0);
		COMMON_PRINTF("IAS Report Is Nonce Match:          %s \n", isNonceMatch ? "Yes!" : "No!");
		if (!isNonceMatch)
		{
			return false;
		}
	}

	std::string quoteBodyB64 = jsonDoc["isvEnclaveQuoteBody"].GetString();
	sgx_quote_t quoteBody;
	DeserializeStruct(quoteBody, quoteBodyB64);

	const sgx_measurement_t& enclaveHash = quoteBody.report_body.mr_enclave;
	bool isProgHashMatch = (SerializeStruct(enclaveHash) == progHash);
	COMMON_PRINTF("IAS Report Is Program Hash Match:   %s \n", isProgHashMatch ? "Yes!" : "No!");

	const sgx_report_data_t& reportData = quoteBody.report_body.report_data;
	bool isReportDataMatch = rdVerifier(oriRD.d, std::vector<uint8_t>(reportData.d, reportData.d + sizeof(sgx_report_data_t)));
	COMMON_PRINTF("IAS Report Is Report Data Match:    %s \n", isReportDataMatch ? "Yes!" : "No!");

#ifndef SIMULATING_ENCLAVE
	return certVerRes && signVerRes && isProgHashMatch && isReportDataMatch;
#else
	return isProgHashMatch && isReportDataMatch;
#endif // !SIMULATING_ENCLAVE
}
