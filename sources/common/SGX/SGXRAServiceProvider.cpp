#include "SGXRAServiceProvider.h"

#include <cstdlib>
#include <string>
#include <map>
#include <mutex>
#include <memory>

#include <openssl/x509.h>

#include <sgx_quote.h>
#include <sgx_key_exchange.h>

#include <rapidjson/document.h>

#include <cppcodec/base64_rfc4648.hpp>

#include "../../common/CommonTool.h"
#include "../../common/CryptoTools.h"
#include "../../common/NonceGenerator.h"
#include "../../common/EnclaveRAState.h"
#include "../../common/RAKeyManager.h"
#include "../../common/SGX/ias_report_cert.h"
#include "../../common/SGX/sgx_crypto_tools.h"
#include "../../common/SGX/sgx_constants.h"
#include "../../common/SGX/sgx_ra_msg4.h"

struct RASPContext
{
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
	static std::mutex m_sgxSPIDMutex;
	static sgx_spid_t g_sgxSPID = { { 0	} };

	static std::string g_selfHash = "";
	static std::map<std::string, std::unique_ptr<RASPContext>> g_clientsMap;

	static std::shared_ptr<RACryptoManager> g_cryptoMgr = std::make_shared<RACryptoManager>();
}

void SGXRAEnclave::SetServerCryptoManager(std::shared_ptr<RACryptoManager> cryptMgr)
{
	g_cryptoMgr = cryptMgr;
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
	g_selfHash = hashBase64;
}

void SGXRAEnclave::SetSPID(const sgx_spid_t & spid)
{
	std::lock_guard<std::mutex> lock(m_sgxSPIDMutex);
	std::memcpy(&g_sgxSPID, &spid, sizeof(sgx_spid_t));
}

sgx_status_t SGXRAEnclave::ServiceProviderInit()
{
	sgx_status_t res = SGX_SUCCESS;
	if (g_cryptoMgr->GetStatus() != SGX_SUCCESS)
	{
		return g_cryptoMgr->GetStatus(); //Error return. (Error from SGX)
	}

	COMMON_PRINTF("SP's public Sign Key: %s\n", SerializePubKey(g_cryptoMgr->GetSignPubKey()).c_str());

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

//sgx_status_t SGXRAEnclave::GetRASPEncrPubKey(sgx_ra_context_t context, sgx_ec256_public_t * outKey)
//{
//	if (!outKey)
//	{
//		return SGX_ERROR_INVALID_PARAMETER;
//	}
//	if (g_cryptoMgr.GetStatus() != SGX_SUCCESS)
//	{
//		return g_cryptoMgr.GetStatus();
//	}
//
//	std::memcpy(outKey, &(g_cryptoMgr.GetEncrPubKey()), sizeof(sgx_ec256_public_t));
//	return SGX_SUCCESS;
//}

sgx_status_t SGXRAEnclave::GetRASPSignPubKey(sgx_ec256_public_t * outKey)
{
	if (!outKey)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}
	if (g_cryptoMgr->GetStatus() != SGX_SUCCESS)
	{
		return g_cryptoMgr->GetStatus();
	}

	std::memcpy(outKey, &(g_cryptoMgr->GetSignPubKey()), sizeof(sgx_ec256_public_t));
	return SGX_SUCCESS;
}

sgx_status_t SGXRAEnclave::ProcessRaMsg0Send(const char* clientID)
{
	if (!clientID)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}
	//std::map<std::string, std::pair<ClientRAState, RAKeyManager>>& clientsMap = EnclaveState::GetInstance().GetClientsMap();
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
	memcpy(&(outMsg2->spid), &g_sgxSPID, sizeof(g_sgxSPID));
	outMsg2->quote_type = SGX_QUOTE_LINKABLE_SIGNATURE;

	outMsg2->kdf_id = SAMPLE_AES_CMAC_KDF_ID;

	sgx_ec256_public_t gb_ga[2];
	memcpy(&gb_ga[0], &(spCTX.m_pubKey), sizeof(sgx_ec256_public_t));
	memcpy(&gb_ga[1], &(spCTX.m_peerEncrKey), sizeof(sgx_ec256_public_t));

	res = sgx_ecdsa_sign((uint8_t *)&gb_ga, sizeof(gb_ga), const_cast<sgx_ec256_private_t*>(&(g_cryptoMgr->GetSignPriKey())), &(outMsg2->sign_gb_ga), g_cryptoMgr->GetECC());
	if (res != SGX_SUCCESS)
	{
		SGXRAEnclave::DropClientRAState(clientID);
		return res; //Error return. (Error from SGX)
	}
	uint8_t mac[SAMPLE_EC_MAC_SIZE] = { 0 };
	uint32_t cmac_size = offsetof(sgx_ra_msg2_t, mac);
	res = sgx_rijndael128_cmac_msg(reinterpret_cast<sgx_cmac_128bit_key_t*>(&(spCTX.m_smk)), (uint8_t *)&(outMsg2->g_b), cmac_size, &mac);
	memcpy(&(outMsg2->mac), mac, sizeof(mac));

	outMsg2->sig_rl_size = 0;

	spCTX.m_state = ClientRAState::MSG1_DONE;

	return res; //Error return. (Error from SGX)
}

sgx_status_t SGXRAEnclave::ProcessRaMsg3(const char* clientID, const uint8_t* inMsg3, uint32_t msg3Len, const char* iasReport, const char* reportSign, const char* reportCert, sgx_ra_msg4_t* outMsg4, sgx_ec256_signature_t* outMsg4Sign)
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

	const sgx_quote_t* p_quote = reinterpret_cast<const sgx_quote_t *>(msg3->quote);

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
	
	if (spCTX.m_reportDataVerifier(report_data.d, std::vector<uint8_t>(p_quote->report_body.report_data.d, p_quote->report_body.report_data.d + sizeof(report_data))))
	{
		SGXRAEnclave::DropClientRAState(clientID);
		//Error return. (Error caused by invalid input.)
		FUNC_ERR("Processing msg3, report_data doesn't match!");
	}

	const sgx_measurement_t& enclaveHash = p_quote->report_body.mr_enclave;
	COMMON_PRINTF("Enclave Program Hash: %s\n", SerializeStruct(enclaveHash).c_str());
	if (SerializeStruct(enclaveHash) != g_selfHash)
	{
		SGXRAEnclave::DropClientRAState(clientID);
		//Error return. (Error caused by invalid input.)
		FUNC_ERR("Processing msg3, enclave program hash doesn't match!");
	}

	//TODO: Verify quote report here.
#ifdef SIMULATING_ENCLAVE
	COMMON_PRINTF("IAS Report Certs Verify Result:     %s \n", "Simulated!");
	COMMON_PRINTF("IAS Report Signature Verify Result: %s \n", "Simulated!");
	outMsg4->status = ias_quote_status_t::IAS_QUOTE_OK;
	//outMsg4->id = 222;

#else
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
		SGXRAEnclave::DropClientRAState(clientID);
		//Error return. (Error caused by invalid input.)
		FUNC_ERR("Processing msg3, IAS report signature invalid!");
	}

	rapidjson::Document jsonDoc;
	jsonDoc.Parse(iasReport);
	outMsg4->status = ParseIASQuoteStatus(jsonDoc["isvEnclaveQuoteStatus"].GetString());
	COMMON_PRINTF("IAS Report Verify Result:           %s \n", outMsg4->status == ias_quote_status_t::IAS_QUOTE_OK ? "Success!" : "Failed!");

	std::string msg3QuoteBody = cppcodec::base64_rfc4648::encode(reinterpret_cast<const uint8_t*>(p_quote), sizeof(sgx_quote_t) - sizeof(p_quote->signature_len));
	std::string reportQuoteBody = jsonDoc["isvEnclaveQuoteBody"].GetString();
	bool isQuoteBodyMatch = (msg3QuoteBody == reportQuoteBody);
	COMMON_PRINTF("IAS Report Is Quote Match:          %s \n", isQuoteBodyMatch ? "Yes!" : "No!");
	if (!isQuoteBodyMatch)
	{
		SGXRAEnclave::DropClientRAState(clientID);
		//Error return. (Error caused by invalid input.)
		FUNC_ERR("Processing msg3, quote body doesn't match!");
	}

	std::string iasNonceReport(jsonDoc["nonce"].GetString());
	const std::string& iasNonceLocal = spCTX.m_nonce;
	bool isNonceMatch = (iasNonceReport == iasNonceLocal);
	COMMON_PRINTF("IAS Report Is Nonce Match:          %s \n", isNonceMatch ? "Yes!" : "No!");
	if (!isNonceMatch)
	{
		SGXRAEnclave::DropClientRAState(clientID);
		//Error return. (Error caused by invalid input.)
		FUNC_ERR("Processing msg3, nonce doesn't match!");
	}

#endif // SIMULATING_ENCLAVE


	//Temporary code here:
	outMsg4->pse_status = ias_pse_status_t::IAS_PSE_OK;

	res = sgx_ecdsa_sign((uint8_t *)outMsg4, sizeof(sgx_ra_msg4_t), const_cast<sgx_ec256_private_t*>(&(g_cryptoMgr->GetSignPriKey())), outMsg4Sign, g_cryptoMgr->GetECC());
	if (res != SGX_SUCCESS)
	{
		SGXRAEnclave::DropClientRAState(clientID);
		return res; //Error return. (Error from SGX)
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
