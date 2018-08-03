#include "Enclave_t.h"
#include "SGXRASP.h"

#include <string>

#include <openssl/x509.h>

#include <sgx_utils.h>

#include <rapidjson/document.h>

#include <cppcodec/base64_rfc4648.hpp>

#include "../common_enclave/EnclaveStatus.h"
#include "../common_enclave/DecentError.h"

#include "../common/CryptoTools.h"
#include "../common/ias_report_cert.h"
#include "../common/sgx_crypto_tools.h"
#include "../common/sgx_constants.h"
#include "../common/sgx_ra_msg4.h"

#include "Enclave.h"

namespace
{
	sgx_spid_t sgxSPID = { {
			0xDD,
			0x16,
			0x40,
			0xFE,
			0x0D,
			0x28,
			0xC9,
			0xA8,
			0xB3,
			0x05,
			0xAF,
			0x4D,
			0x4E,
			0x76,
			0x58,
			0xBE,
		} };
	
	std::string g_selfHash = "";
}

void DropClientRAState(const std::string& clientID)
{
	auto it = EnclaveState::GetInstance().GetClientsMap().find(clientID);
	if (it != EnclaveState::GetInstance().GetClientsMap().end())
	{
		EnclaveState::GetInstance().GetClientsMap().erase(it);
	}
}

sgx_status_t ecall_init_ra_sp_environment()
{
	DecentCryptoManager& cryptoMgr = EnclaveState::GetInstance().GetCryptoMgr();
	sgx_status_t res = SGX_SUCCESS;
	if (cryptoMgr.GetStatus() != SGX_SUCCESS)
	{
		return cryptoMgr.GetStatus(); //Error return. (Error from SGX)
	}

	enclave_printf("Public Sign Key: %s\n", SerializePubKey(cryptoMgr.GetSignPubKey()).c_str());
	enclave_printf("Public Encr Key: %s\n", SerializePubKey(cryptoMgr.GetEncrPubKey()).c_str());

	sgx_report_t selfReport;
	res = sgx_create_report(nullptr, nullptr, &selfReport);
	if (res != SGX_SUCCESS)
	{
		return res; //Error return. (Error from SGX)
	}
	sgx_measurement_t& enclaveHash = selfReport.body.mr_enclave;
	enclave_printf("Enclave Program Hash: %s\n", SerializeStruct(enclaveHash).c_str());
	g_selfHash = SerializeStruct(enclaveHash);

	return SGX_SUCCESS;
}

sgx_status_t ecall_process_ra_msg0_send(const char* clientID)
{
	std::map<std::string, std::pair<ClientRAState, RAKeyManager>>& clientsMap = EnclaveState::GetInstance().GetClientsMap();
	sgx_ec256_public_t clientSignkey;
	DeserializePubKey(clientID, clientSignkey);
	auto it = clientsMap.find(clientID);
	if (it != clientsMap.end())
	{
		//Error return. (Error caused by invalid input.)
		FUNC_ERR("Processing msg0, but client ID already exist.");
	}
	clientsMap.insert(std::make_pair<std::string, std::pair<ClientRAState, RAKeyManager> >(clientID, std::make_pair<ClientRAState, RAKeyManager>(ClientRAState::MSG0_DONE, RAKeyManager(clientSignkey))));

	return SGX_SUCCESS;
}

sgx_status_t ecall_process_ra_msg1(const char* clientID, const sgx_ra_msg1_t *inMsg1, sgx_ra_msg2_t *outMsg2)
{
	std::map<std::string, std::pair<ClientRAState, RAKeyManager>>& clientsMap = EnclaveState::GetInstance().GetClientsMap();
	DecentCryptoManager& cryptoMgr = EnclaveState::GetInstance().GetCryptoMgr();
	auto it = clientsMap.find(clientID);
	if (it == clientsMap.end()
		|| it->second.first != ClientRAState::MSG0_DONE)
	{
		DropClientRAState(clientID);
		//Error return. (Error caused by invalid input.)
		FUNC_ERR("Processing msg1, but client ID doesn't exist or in a invalid state.");
	}

	RAKeyManager& clientKeyMgr = it->second.second;

	sgx_status_t res = SGX_SUCCESS;

	clientKeyMgr.SetEncryptKey((inMsg1->g_a));

	res = clientKeyMgr.GenerateSharedKeySet(cryptoMgr.GetEncrPriKey(), cryptoMgr.GetECC());
	if (res != SGX_SUCCESS)
	{
		DropClientRAState(clientID);
		return res; //Error return. (Error from SGX)
	}

	memcpy(&(outMsg2->g_b), &(cryptoMgr.GetEncrPubKey()), sizeof(sgx_ec256_public_t));
	memcpy(&(outMsg2->spid), &sgxSPID, sizeof(sgxSPID));
	outMsg2->quote_type = SGX_QUOTE_LINKABLE_SIGNATURE;

	outMsg2->kdf_id = SAMPLE_AES_CMAC_KDF_ID;

	sgx_ec256_public_t gb_ga[2];
	memcpy(&gb_ga[0], &(cryptoMgr.GetEncrPubKey()), sizeof(sgx_ec256_public_t));
	memcpy(&gb_ga[1], &(clientKeyMgr.GetEncryptKey()), sizeof(sgx_ec256_public_t));

	res = sgx_ecdsa_sign((uint8_t *)&gb_ga, sizeof(gb_ga), const_cast<sgx_ec256_private_t*>(&(cryptoMgr.GetSignPriKey())), &(outMsg2->sign_gb_ga), cryptoMgr.GetECC());
	if (res != SGX_SUCCESS)
	{
		DropClientRAState(clientID);
		return res; //Error return. (Error from SGX)
	}
	uint8_t mac[SAMPLE_EC_MAC_SIZE] = { 0 };
	uint32_t cmac_size = offsetof(sgx_ra_msg2_t, mac);
	res = sgx_rijndael128_cmac_msg(reinterpret_cast<sgx_cmac_128bit_key_t*>(clientKeyMgr.GetSMK()), (uint8_t *)&(outMsg2->g_b), cmac_size, &mac);
	memcpy(&(outMsg2->mac), mac, sizeof(mac));

	outMsg2->sig_rl_size = 0;

	it->second.first = ClientRAState::MSG1_DONE;

	return res; //Error return. (Error from SGX)
}

sgx_status_t ecall_process_ra_msg3(const char* clientID, const uint8_t* inMsg3, uint32_t msg3Len, const char* iasReport, const char* reportSign, const char* reportCert, sgx_ra_msg4_t* outMsg4, sgx_ec256_signature_t* outMsg4Sign)
{
	DecentCryptoManager& cryptoMgr = EnclaveState::GetInstance().GetCryptoMgr();
	auto it = EnclaveState::GetInstance().GetClientsMap().find(clientID);
	if (it == EnclaveState::GetInstance().GetClientsMap().end()
		|| it->second.first != ClientRAState::MSG1_DONE)
	{
		DropClientRAState(clientID);
		//Error return. (Error caused by invalid input.)
		FUNC_ERR("Processing msg3, but client ID doesn't exist or in a invalid state.");
	}

	RAKeyManager& clientKeyMgr = it->second.second;

	sgx_status_t res = SGX_SUCCESS;
	int cmpRes = 0;
	const sgx_ra_msg3_t* msg3 = reinterpret_cast<const sgx_ra_msg3_t*>(inMsg3);

	// Compare g_a in message 3 with local g_a.
	cmpRes = std::memcmp(&(clientKeyMgr.GetEncryptKey()), &msg3->g_a, sizeof(sgx_ec256_public_t));
	if (cmpRes)
	{
		DropClientRAState(clientID);
		//Error return. (Error caused by invalid input.)
		FUNC_ERR("Processing msg3, g_a doesn't match!");
	}

	//Make sure that msg3_size is bigger than sgx_mac_t.
	uint32_t mac_size = msg3Len - sizeof(sgx_mac_t);
	const uint8_t *p_msg3_cmaced = inMsg3;
	p_msg3_cmaced += sizeof(sgx_mac_t);

	res = verify_cmac128(&(clientKeyMgr.GetSMK()), p_msg3_cmaced, mac_size, (msg3->mac));
	if (res != SGX_SUCCESS)
	{
		DropClientRAState(clientID);
		return res; //Error return. (Error from SGX)
	}

	clientKeyMgr.SetSecProp(msg3->ps_sec_prop);

	const sgx_quote_t* p_quote = reinterpret_cast<const sgx_quote_t *>(msg3->quote);

	sgx_sha_state_handle_t sha_handle = nullptr;
	sgx_report_data_t report_data = { 0 };
	// Verify the report_data in the Quote matches the expected value.
	// The first 32 bytes of report_data are SHA256 HASH of {ga|gb|vk}.
	// The second 32 bytes of report_data are set to zero.
	res = sgx_sha256_init(&sha_handle);
	if (res != SGX_SUCCESS)
	{
		DropClientRAState(clientID);
		return res; //Error return. (Error from SGX)
	}

	res = sgx_sha256_update(reinterpret_cast<const uint8_t*>(&(clientKeyMgr.GetEncryptKey())), sizeof(sgx_ec256_public_t), sha_handle);
	if (res != SGX_SUCCESS)
	{
		DropClientRAState(clientID);
		return res;
	}

	res = sgx_sha256_update(reinterpret_cast<const uint8_t*>(&cryptoMgr.GetEncrPubKey()), sizeof(sgx_ec256_public_t), sha_handle);
	if (res != SGX_SUCCESS)
	{
		DropClientRAState(clientID);
		return res; //Error return. (Error from SGX)
	}

	res = sgx_sha256_update(reinterpret_cast<const uint8_t*>(&(clientKeyMgr.GetVK())), sizeof(sgx_ec_key_128bit_t), sha_handle);
	if (res != SGX_SUCCESS)
	{
		DropClientRAState(clientID);
		return res; //Error return. (Error from SGX)
	}

	res = sgx_sha256_get_hash(sha_handle, (sgx_sha256_hash_t *)&report_data);
	if (res != SGX_SUCCESS)
	{
		DropClientRAState(clientID);
		return res; //Error return. (Error from SGX)
	}

	cmpRes = std::memcmp((uint8_t *)&report_data, (uint8_t *)&(p_quote->report_body.report_data), sizeof(report_data));
	if (cmpRes)
	{
		DropClientRAState(clientID);
		//Error return. (Error caused by invalid input.)
		FUNC_ERR("Processing msg3, report_data doesn't match!");
	}

	const sgx_measurement_t& enclaveHash = p_quote->report_body.mr_enclave;
	enclave_printf("Enclave Program Hash: %s\n", SerializeStruct(enclaveHash).c_str());
	if (SerializeStruct(enclaveHash) != g_selfHash)
	{
		DropClientRAState(clientID);
		//Error return. (Error caused by invalid input.)
		FUNC_ERR("Processing msg3, enclave program hash doesn't match!");
	}
	
	//TODO: Verify quote report here.
#ifdef SIMULATING_ENCLAVE
	enclave_printf("IAS Report Certs Verify Result:     %s \n", "Simulated!");
	enclave_printf("IAS Report Signature Verify Result: %s \n", "Simulated!");
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

	enclave_printf("IAS Report Certs Verify Result:     %s \n", certVerRes ? "Success!" : "Failed!");
	enclave_printf("IAS Report Signature Verify Result: %s \n", signVerRes ? "Success!" : "Failed!");
	if (!certVerRes || !signVerRes)
	{
		DropClientRAState(clientID);
		//Error return. (Error caused by invalid input.)
		FUNC_ERR("Processing msg3, IAS report signature invalid!");
	}

	rapidjson::Document jsonDoc;
	jsonDoc.Parse(iasReport);
	outMsg4->status = ParseIASQuoteStatus(jsonDoc["isvEnclaveQuoteStatus"].GetString());
	enclave_printf("IAS Report Verify Result:           %s \n", outMsg4->status == ias_quote_status_t::IAS_QUOTE_OK ? "Success!" : "Failed!");
	
	std::string msg3QuoteBody = cppcodec::base64_rfc4648::encode(reinterpret_cast<const uint8_t*>(p_quote), sizeof(sgx_quote_t) - sizeof(p_quote->signature_len));
	std::string reportQuoteBody = jsonDoc["isvEnclaveQuoteBody"].GetString();
	bool isQuoteBodyMatch = (msg3QuoteBody == reportQuoteBody);
	enclave_printf("IAS Report Is Quote Match:          %s \n", isQuoteBodyMatch ? "Yes!" : "No!");
	if (!isQuoteBodyMatch)
	{
		DropClientRAState(clientID);
		//Error return. (Error caused by invalid input.)
		FUNC_ERR("Processing msg3, quote body doesn't match!");
	}

#endif // SIMULATING_ENCLAVE


	//Temporary code here:
	outMsg4->pse_status = ias_pse_status_t::IAS_PSE_OK;

	res = sgx_ecdsa_sign((uint8_t *)outMsg4, sizeof(sgx_ra_msg4_t), const_cast<sgx_ec256_private_t*>(&(cryptoMgr.GetSignPriKey())), outMsg4Sign, cryptoMgr.GetECC());
	if (res != SGX_SUCCESS)
	{
		DropClientRAState(clientID);
		return res; //Error return. (Error from SGX)
	}

	if (outMsg4->status == ias_quote_status_t::IAS_QUOTE_OK)
	{
		it->second.first = ClientRAState::ATTESTED;
	}
	else
	{
		DropClientRAState(clientID);
		//Error return. (Error caused by invalid input.)
		FUNC_ERR("Processing msg3, quote got rejected by IAS!");
	}

	return SGX_SUCCESS;
}

