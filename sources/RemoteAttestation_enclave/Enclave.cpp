#include <map>

#include <sgx_tcrypto.h>
#include <sgx_tkey_exchange.h>

#include <cppcodec/base64_rfc4648.hpp>

#include <rapidjson/rapidjson.h>
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>

#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */

#include "../common_enclave/enclave_tools.h"
#include "../common_enclave/RAConnection.h"
#include "../common_enclave/RAKeyManager.h"
#include "../common_enclave/DecentCryptoManager.h"

#include "../common/CryptoTools.h"
#include "../common/sgx_ra_msg4.h"
#include "../common/Decent.h"

namespace 
{
	sgx_spid_t sgxSPID = { "Decent X" };

	std::map<std::string, std::pair<ServerRAState, RAKeyManager> > g_serversMap;
	std::map<std::string, std::pair<ClientRAState, RAKeyManager> > g_clientsMap;
	DecentCryptoManager g_cryptoMgr;

	DecentNodeMode g_decentMode = DecentNodeMode::ROOT_SERVER;
}

bool IsBothWayAttested(const std::string& id)
{
	auto itServ = g_serversMap.find(id);
	auto itClit = g_clientsMap.find(id);
	if ((itServ == g_serversMap.end())
		|| (itClit == g_clientsMap.end()))
	{
		return false;
	}
	if ((itClit->second.first != ClientRAState::ATTESTED)
		|| (itServ->second.first != ServerRAState::ATTESTED))
	{
		return false;
	}

	return true;
}

bool AdjustSharedKeysServ(const std::string& id)
{
	if (!IsBothWayAttested(id))
	{
		return false;
	}
	auto itServ = g_serversMap.find(id);
	auto itClit = g_clientsMap.find(id);

	itClit->second.second.SetSMK(itServ->second.second.GetSMK());
	itClit->second.second.SetSK(itServ->second.second.GetSK());
	itClit->second.second.SetMK(itServ->second.second.GetMK());
	itClit->second.second.SetVK(itServ->second.second.GetVK());

	enclave_printf("Adjusted Skey: %s\n", SerializeKey(itClit->second.second.GetSK()).c_str());
	return true;
}

bool AdjustSharedKeysClit(const std::string& id)
{
	if (!IsBothWayAttested(id))
	{
		return false;
	}
	auto itServ = g_serversMap.find(id);
	auto itClit = g_clientsMap.find(id);

	itServ->second.second.SetSMK(itClit->second.second.GetSMK());
	itServ->second.second.SetSK(itClit->second.second.GetSK());
	itServ->second.second.SetMK(itClit->second.second.GetMK());
	itServ->second.second.SetVK(itClit->second.second.GetVK());

	enclave_printf("Adjusted Skey: %s\n", SerializeKey(itServ->second.second.GetSK()).c_str());
	return true;
}

int EC_KEY_get_asn1_flag(const EC_KEY* key)
{
	if (key)
	{
		const EC_GROUP* group = EC_KEY_get0_group(key);
		if (group)
		{
			return EC_GROUP_get_asn1_flag(group);
		}
		return 0;
	}
}

static void DropClientRAState(const std::string& clientID)
{
	auto it = g_clientsMap.find(clientID);
	if (it != g_clientsMap.end())
	{
		g_clientsMap.erase(it);
	}
}

static void DropServerRAState(const std::string& serverID)
{
	auto it = g_serversMap.find(serverID);
	if (it != g_serversMap.end())
	{
		g_serversMap.erase(it);
	}
}

//sgx_status_t ecall_get_ra_pub_enc_key(sgx_ra_context_t context, sgx_ec256_public_t* outKey)
//{
//	sgx_status_t res = SGX_SUCCESS;
//	res = ecall_generate_ra_keys();
//
//	if (res != SGX_SUCCESS)
//	{
//		return res;
//	}
//	memcpy(outKey, sgxRAPubkey, sizeof(sgx_ec256_public_t));
//	return res;
//}

sgx_status_t ecall_get_ra_pub_sig_key(sgx_ra_context_t context, sgx_ec256_public_t* outKey)
{
	sgx_status_t res = SGX_SUCCESS;
	if (g_cryptoMgr.GetStatus() != SGX_SUCCESS)
	{
		return g_cryptoMgr.GetStatus();
	}

	std::memcpy(outKey, &(g_cryptoMgr.GetSignPubKey()), sizeof(sgx_ec256_public_t));
	return res;
}

static sgx_status_t enclave_init_ra(const sgx_ec256_public_t *p_pub_key, int b_pse, sgx_ra_context_t *p_context)
{
	// isv enclave call to trusted key exchange library.
	sgx_status_t ret;
	if (b_pse)
	{
		//int busy_retry_times = 2; do {} while (ret == SGX_ERROR_BUSY && busy_retry_times--);
		ret = sgx_create_pse_session();
		if (ret != SGX_SUCCESS)
			return ret;
	}
	ret = sgx_ra_init(p_pub_key, b_pse, p_context);

	//Debug Code:
	//std::string raPubKeyStr;
	//raPubKeyStr = SerializePubKey(*sgxRARemotePubkey);
	//enclave_printf("RA ContextID: %d\n", *p_context);
	//enclave_printf("RA Remote Signing Key: %s\n", raPubKeyStr.c_str());
	////////////////////

	if (b_pse)
	{
		sgx_close_pse_session();
	}
	return ret;
}

sgx_status_t ecall_init_ra_environment()
{
	sgx_status_t res = SGX_SUCCESS;
	if (g_cryptoMgr.GetStatus() != SGX_SUCCESS)
	{
		return g_cryptoMgr.GetStatus();
	}

	std::string raPubKeyStr;
	raPubKeyStr = SerializePubKey(g_cryptoMgr.GetSignPubKey());
	enclave_printf("Public key string: %s\n", raPubKeyStr.c_str());
	//raPubKeyStr = SerializePubKey(sgxRAPubkey);
	//enclave_printf("Public key string: %s\n", raPubKeyStr.c_str());

	//CleanRAKeys();

	return res;
}

sgx_status_t ecall_process_ra_msg0_send(const char* clientID)
{
	sgx_ec256_public_t clientSignkey;
	DeserializePubKey(clientID, clientSignkey);
	auto it = g_clientsMap.find(clientID);
	if (it != g_clientsMap.end())
	{
		return SGX_ERROR_UNEXPECTED;
	}
	g_clientsMap.insert(std::make_pair<std::string, std::pair<ClientRAState, RAKeyManager> >(clientID, std::make_pair<ClientRAState, RAKeyManager>(ClientRAState::MSG0_DONE, RAKeyManager(clientSignkey))));

	return SGX_SUCCESS;
}

sgx_status_t ecall_process_ra_msg0_resp(const char* ServerID, const sgx_ec256_public_t* inPubKey, int enablePSE, sgx_ra_context_t* outContextID)
{
	auto it = g_serversMap.find(ServerID);
	if (it != g_serversMap.end())
	{
		return SGX_ERROR_UNEXPECTED;
	}
	g_serversMap.insert(std::make_pair<std::string, std::pair<ServerRAState, RAKeyManager> >(ServerID, std::make_pair<ServerRAState, RAKeyManager>(ServerRAState::MSG0_DONE, RAKeyManager(*inPubKey))));
	
	return enclave_init_ra(inPubKey, enablePSE, outContextID);
}

sgx_status_t ecall_process_ra_msg1(const char* clientID, const sgx_ra_msg1_t *inMsg1, sgx_ra_msg2_t *outMsg2)
{
	auto it = g_clientsMap.find(clientID);
	if (it == g_clientsMap.end()
		|| it->second.first != ClientRAState::MSG0_DONE)
	{
		DropClientRAState(clientID);
		return SGX_ERROR_UNEXPECTED;
	}
	
	RAKeyManager& clientKeyMgr = it->second.second;

	sgx_status_t res = SGX_SUCCESS;

	clientKeyMgr.SetEncryptKey((inMsg1->g_a));

	sgx_ec256_dh_shared_t sharedKey;
	res = sgx_ecc256_compute_shared_dhkey(const_cast<sgx_ec256_private_t*>(&(g_cryptoMgr.GetEncrPriKey())), &(clientKeyMgr.GetEncryptKey()), &sharedKey, g_cryptoMgr.GetECC());
	if (res != SGX_SUCCESS)
	{
		DropClientRAState(clientID);
		return res;
	}
	clientKeyMgr.SetSharedKey(sharedKey);

	sgx_ec_key_128bit_t tmpDerivedKey;
	bool keyDeriveRes = false;
	keyDeriveRes = derive_key(&(clientKeyMgr.GetSharedKey()), SAMPLE_DERIVE_KEY_SMK, &tmpDerivedKey);
	if (!keyDeriveRes)
	{
		DropClientRAState(clientID);
		return SGX_ERROR_UNEXPECTED;
	}
	clientKeyMgr.SetSMK(tmpDerivedKey);
	keyDeriveRes = derive_key(&(clientKeyMgr.GetSharedKey()), SAMPLE_DERIVE_KEY_MK, &tmpDerivedKey);
	if (!keyDeriveRes)
	{
		DropClientRAState(clientID);
		return SGX_ERROR_UNEXPECTED;
	}
	clientKeyMgr.SetMK(tmpDerivedKey);
	keyDeriveRes = derive_key(&(clientKeyMgr.GetSharedKey()), SAMPLE_DERIVE_KEY_SK, &tmpDerivedKey);
	if (!keyDeriveRes)
	{
		DropClientRAState(clientID);
		return SGX_ERROR_UNEXPECTED;
	}
	clientKeyMgr.SetSK(tmpDerivedKey);
	keyDeriveRes = derive_key(&(clientKeyMgr.GetSharedKey()), SAMPLE_DERIVE_KEY_VK, &tmpDerivedKey);
	if (!keyDeriveRes)
	{
		DropClientRAState(clientID);
		return SGX_ERROR_UNEXPECTED;
	}
	clientKeyMgr.SetVK(tmpDerivedKey);

	memcpy(&(outMsg2->g_b), &(g_cryptoMgr.GetEncrPubKey()), sizeof(sgx_ec256_public_t));
	memcpy(&(outMsg2->spid), &sgxSPID, sizeof(sgxSPID));
	outMsg2->quote_type = SGX_QUOTE_LINKABLE_SIGNATURE;

	outMsg2->kdf_id = SAMPLE_AES_CMAC_KDF_ID;

	sgx_ec256_public_t gb_ga[2];
	memcpy(&gb_ga[0], &(g_cryptoMgr.GetEncrPubKey()), sizeof(sgx_ec256_public_t));
	memcpy(&gb_ga[1], &(clientKeyMgr.GetEncryptKey()), sizeof(sgx_ec256_public_t));

	res = sgx_ecdsa_sign((uint8_t *)&gb_ga, sizeof(gb_ga), const_cast<sgx_ec256_private_t*>(&(g_cryptoMgr.GetSignPriKey())), &(outMsg2->sign_gb_ga), g_cryptoMgr.GetECC());
	if (res != SGX_SUCCESS)
	{
		DropClientRAState(clientID);
		return res;
	}
	uint8_t mac[SAMPLE_EC_MAC_SIZE] = { 0 };
	uint32_t cmac_size = offsetof(sgx_ra_msg2_t, mac);
	res = sgx_rijndael128_cmac_msg(reinterpret_cast<sgx_cmac_128bit_key_t*>(clientKeyMgr.GetSMK()), (uint8_t *)&(outMsg2->g_b), cmac_size, &mac);
	memcpy(&(outMsg2->mac), mac, sizeof(mac));

	outMsg2->sig_rl_size = 0;

	it->second.first = ClientRAState::MSG1_DONE;

	return res;
}

sgx_status_t ecall_process_ra_msg2(const char* ServerID, sgx_ra_context_t inContextID)
{
	auto it = g_serversMap.find(ServerID);
	if (it == g_serversMap.end()
		|| it->second.first != ServerRAState::MSG0_DONE)
	{
		DropServerRAState(ServerID);
		return SGX_ERROR_UNEXPECTED;
	}

	RAKeyManager& serverKeyMgr = it->second.second;

	sgx_status_t res = SGX_SUCCESS;

	sgx_ra_key_128_t tmpKey;
	res = sgx_ra_get_keys(inContextID, SGX_RA_KEY_SK, &tmpKey);
	if (res != SGX_SUCCESS)
	{
		return res;
	}
	serverKeyMgr.SetSK(tmpKey);
	res = sgx_ra_get_keys(inContextID, SGX_RA_KEY_MK, &tmpKey);
	if (res != SGX_SUCCESS)
	{
		return res;
	}
	serverKeyMgr.SetMK(tmpKey);
	//res = sgx_ra_get_keys(inContextID, SGX_RA_KEY_VK, &tmpKey);
	//if (res != SGX_SUCCESS)
	//{
	//	return res;
	//}
	//serverKeyMgr.SetVK(tmpKey);

	it->second.first = ServerRAState::MSG2_DONE;

	return res;
}

sgx_status_t ecall_process_ra_msg3(const char* clientID, const uint8_t* inMsg3, uint32_t msg3Len, const char* iasReport, const char* reportSign, sgx_ra_msg4_t* outMsg4, sgx_ec256_signature_t* outMsg4Sign)
{
	auto it = g_clientsMap.find(clientID);
	if (it == g_clientsMap.end()
		|| it->second.first != ClientRAState::MSG1_DONE)
	{
		DropClientRAState(clientID);
		return SGX_ERROR_UNEXPECTED;
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
		return SGX_ERROR_UNEXPECTED;
	}

	//Make sure that msg3_size is bigger than sample_mac_t.
	uint32_t mac_size = msg3Len - sizeof(sgx_mac_t);
	const uint8_t *p_msg3_cmaced = inMsg3;
	p_msg3_cmaced += sizeof(sgx_mac_t);

	// Verify the message mac using SMK
	sgx_cmac_128bit_tag_t mac = { 0 };
	res = sgx_rijndael128_cmac_msg(&(clientKeyMgr.GetSMK()), p_msg3_cmaced, mac_size, &mac);
	if (res != SGX_SUCCESS)
	{
		DropClientRAState(clientID);
		return res;
	}

	// In real implementation, should use a time safe version of memcmp here,
	// in order to avoid side channel attack.
	cmpRes = std::memcmp(&(msg3->mac), mac, sizeof(mac));
	if (cmpRes)
	{
		DropClientRAState(clientID);
		return SGX_ERROR_UNEXPECTED;
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
		return res;
	}

	res = sgx_sha256_update(reinterpret_cast<const uint8_t*>(&(clientKeyMgr.GetEncryptKey())), sizeof(sgx_ec256_public_t), sha_handle);
	if (res != SGX_SUCCESS)
	{
		DropClientRAState(clientID);
		return res;
	}

	res = sgx_sha256_update(reinterpret_cast<const uint8_t*>(&g_cryptoMgr.GetEncrPubKey()), sizeof(sgx_ec256_public_t), sha_handle);
	if (res != SGX_SUCCESS)
	{
		DropClientRAState(clientID);
		return res;
	}

	res = sgx_sha256_update(reinterpret_cast<const uint8_t*>(&(clientKeyMgr.GetVK())), sizeof(sgx_ec_key_128bit_t), sha_handle);
	if (res != SGX_SUCCESS)
	{
		DropClientRAState(clientID);
		return res;
	}

	res = sgx_sha256_get_hash(sha_handle, (sgx_sha256_hash_t *)&report_data);
	if (res != SGX_SUCCESS)
	{
		DropClientRAState(clientID);
		return res;
	}

	cmpRes = std::memcmp((uint8_t *)&report_data, (uint8_t *)&(p_quote->report_body.report_data), sizeof(report_data));
	if (cmpRes)
	{
		DropClientRAState(clientID);
		return SGX_ERROR_UNEXPECTED;
	}

	//TODO: Verify quote report here.

	//Temporary code here:
	outMsg4->id = 222;
	outMsg4->pse_status = ias_pse_status_t::IAS_PSE_OK;
	outMsg4->status = ias_quote_status_t::IAS_QUOTE_OK;

	res = sgx_ecdsa_sign((uint8_t *)outMsg4, sizeof(sgx_ra_msg4_t), const_cast<sgx_ec256_private_t*>(&(g_cryptoMgr.GetSignPriKey())), outMsg4Sign, g_cryptoMgr.GetECC());
	if (res != SGX_SUCCESS)
	{
		DropClientRAState(clientID);
		return res;
	}

	it->second.first = ClientRAState::ATTESTED;

	AdjustSharedKeysClit(clientID);

	enclave_printf("Current Skey: %s\n", SerializeKey(clientKeyMgr.GetSK()).c_str());

	return res;
}

sgx_status_t ecall_process_ra_msg4(const char* ServerID, const sgx_ra_msg4_t* inMsg4, sgx_ec256_signature_t* inMsg4Sign, sgx_ra_context_t inContextID)
{
	auto it = g_serversMap.find(ServerID);
	if (it == g_serversMap.end()
		|| it->second.first != ServerRAState::MSG2_DONE)
	{
		DropServerRAState(ServerID);
		return SGX_ERROR_UNEXPECTED;
	}

	RAKeyManager& serverKeyMgr = it->second.second;

	sgx_status_t res = SGX_SUCCESS;

	uint8_t signVerifyRes = 0;
	res = sgx_ecdsa_verify((uint8_t *)inMsg4, sizeof(sgx_ra_msg4_t), &(serverKeyMgr.GetSignKey()), inMsg4Sign, &signVerifyRes, g_cryptoMgr.GetECC());
	if (signVerifyRes != SGX_EC_VALID)
	{
		DropServerRAState(ServerID);
		return SGX_ERROR_UNEXPECTED;
	}
	if (inMsg4->status != ias_quote_status_t::IAS_QUOTE_OK)
	{
		DropServerRAState(ServerID);
		return SGX_ERROR_UNEXPECTED;
	}

	it->second.first = ServerRAState::ATTESTED;

	sgx_ra_close(inContextID);

	AdjustSharedKeysServ(ServerID);

	enclave_printf("Current Skey: %s\n", SerializeKey(serverKeyMgr.GetSK()).c_str());

	return res;
}

sgx_status_t ecall_termination_clean()
{
	//CleanRAKeys();

	//if (!g_eccContext)
	//{
	//	sgx_ecc256_close_context(g_eccContext);
	//	g_eccContext = nullptr;
	//}

	g_serversMap.clear();
	g_clientsMap.clear();

	return SGX_SUCCESS;
}

void GenSSLECKeys()
{
	EC_KEY *key = nullptr; 
	EVP_PKEY *pkey = NULL;
	int eccgrp;
	int res = 0;

	key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if (!key)
	{
		enclave_printf("Gen key failed. - 0\n");
	}

	EC_KEY_set_asn1_flag(key, OPENSSL_EC_NAMED_CURVE);

	res = EC_KEY_generate_key(key);
	if (!res)
	{
		enclave_printf("Gen key failed. - 1\n");
	}

	pkey = EVP_PKEY_new();

	res = EVP_PKEY_assign_EC_KEY(pkey, key);
	if (!res)
	{
		enclave_printf("Gen key failed. - 2\n");
	}


	//BIGNUM *prv = nullptr;
	//EC_POINT *pub = nullptr;

	//EC_KEY_set_private_key(key, prv);
	//EC_KEY_set_public_key(key, pub);
}

#define EC_DERIVATION_BUFFER_SIZE(label_length) ((label_length) +4)

const char str_SMK[] = "SMK";
const char str_SK[] = "SK";
const char str_MK[] = "MK";
const char str_VK[] = "VK";

// Derive key from shared key and key id.
// key id should be sample_derive_key_type_t.
bool derive_key(const sgx_ec256_dh_shared_t *p_shared_key, uint8_t key_id, sgx_ec_key_128bit_t* derived_key)
{
	sgx_status_t sample_ret = SGX_SUCCESS;
	sgx_cmac_128bit_key_t cmac_key;
	sgx_ec_key_128bit_t key_derive_key;

	memset(&cmac_key, 0, sizeof(cmac_key));

	sample_ret = sgx_rijndael128_cmac_msg(&cmac_key, (uint8_t*)p_shared_key, sizeof(sgx_ec256_dh_shared_t), (sgx_cmac_128bit_tag_t *)&key_derive_key);
	if (sample_ret != SGX_SUCCESS)
	{
		// memset here can be optimized away by compiler, so please use memset_s on
		// windows for production code and similar functions on other OSes.
		memset(&key_derive_key, 0, sizeof(key_derive_key));
		return false;
	}
	
	const char *label = NULL;
	uint32_t label_length = 0;
	switch (key_id)
	{
	case SAMPLE_DERIVE_KEY_SMK:
		label = str_SMK;
		label_length = sizeof(str_SMK) - 1;
		break;
	case SAMPLE_DERIVE_KEY_SK:
		label = str_SK;
		label_length = sizeof(str_SK) - 1;
		break;
	case SAMPLE_DERIVE_KEY_MK:
		label = str_MK;
		label_length = sizeof(str_MK) - 1;
		break;
	case SAMPLE_DERIVE_KEY_VK:
		label = str_VK;
		label_length = sizeof(str_VK) - 1;
		break;
	default:
		// memset here can be optimized away by compiler, so please use memset_s on
		// windows for production code and similar functions on other OSes.
		memset(&key_derive_key, 0, sizeof(key_derive_key));
		return false;
		break;
	}
	/* derivation_buffer = counter(0x01) || label || 0x00 || output_key_len(0x0080) */
	uint32_t derivation_buffer_length = EC_DERIVATION_BUFFER_SIZE(label_length);
	uint8_t *p_derivation_buffer = (uint8_t *)malloc(derivation_buffer_length);
	if (p_derivation_buffer == NULL)
	{
		// memset here can be optimized away by compiler, so please use memset_s on
		// windows for production code and similar functions on other OSes.
		memset(&key_derive_key, 0, sizeof(key_derive_key));
		return false;
	}
	memset(p_derivation_buffer, 0, derivation_buffer_length);

	/*counter = 0x01 */
	p_derivation_buffer[0] = 0x01;
	/*label*/
	memcpy(&p_derivation_buffer[1], label, derivation_buffer_length - 1);//label_length);
	/*output_key_len=0x0080*/
	uint16_t *key_len = (uint16_t *)(&(p_derivation_buffer[derivation_buffer_length - 2]));
	*key_len = 0x0080;


	sample_ret = sgx_rijndael128_cmac_msg((sgx_cmac_128bit_key_t *)&key_derive_key, p_derivation_buffer, derivation_buffer_length, (sgx_cmac_128bit_tag_t *)derived_key);
	free(p_derivation_buffer);
	// memset here can be optimized away by compiler, so please use memset_s on
	// windows for production code and similar functions on other OSes.
	memset(&key_derive_key, 0, sizeof(key_derive_key));
	if (sample_ret != SGX_SUCCESS)
	{
		return false;
	}
	return true;
}

void ecall_set_decent_mode(DecentNodeMode inDecentMode)
{
	g_decentMode = inDecentMode;
}

DecentNodeMode ecall_get_decent_mode()
{
	return g_decentMode;
}

sgx_status_t ecall_get_protocol_sign_key(const char* clientID, sgx_ec256_private_t* outPriKey, sgx_aes_gcm_128bit_tag_t* outPriKeyMac, sgx_ec256_public_t* outPubKey, sgx_aes_gcm_128bit_tag_t* outPubKeyMac)
{
	if (g_decentMode != DecentNodeMode::ROOT_SERVER)
	{
		return SGX_ERROR_UNEXPECTED;
	}
	if (!IsBothWayAttested(clientID))
	{
		return SGX_ERROR_UNEXPECTED;
	}

	auto it = g_clientsMap.find(clientID);

	RAKeyManager& clientKeyMgr = it->second.second;

	sgx_status_t enclaveRes = SGX_SUCCESS;

	uint8_t aes_gcm_iv[SAMPLE_SP_IV_SIZE] = { 0 };
	enclaveRes = sgx_rijndael128GCM_encrypt(&clientKeyMgr.GetSK(), 
		reinterpret_cast<const uint8_t*>(&g_cryptoMgr.GetSignPriKey()), 
		sizeof(sgx_ec256_private_t),
		reinterpret_cast<uint8_t*>(outPriKey),
		aes_gcm_iv,
		SAMPLE_SP_IV_SIZE,
		nullptr,
		0,
		outPriKeyMac
		);
	if (enclaveRes != SGX_SUCCESS)
	{
		return enclaveRes;
	}

	enclaveRes = sgx_rijndael128GCM_encrypt(&clientKeyMgr.GetSK(),
		reinterpret_cast<const uint8_t*>(&g_cryptoMgr.GetSignPubKey()),
		sizeof(sgx_ec256_public_t),
		reinterpret_cast<uint8_t*>(outPubKey),
		aes_gcm_iv,
		SAMPLE_SP_IV_SIZE,
		nullptr,
		0,
		outPubKeyMac
	);

	return enclaveRes;
}

sgx_status_t ecall_get_protocol_encr_key(const char* clientID, sgx_ec256_private_t* outPriKey, sgx_aes_gcm_128bit_tag_t* outPriKeyMac, sgx_ec256_public_t* outPubKey, sgx_aes_gcm_128bit_tag_t* outPubKeyMac)
{
	if (g_decentMode != DecentNodeMode::ROOT_SERVER)
	{
		return SGX_ERROR_UNEXPECTED;
	}
	if (!IsBothWayAttested(clientID))
	{
		return SGX_ERROR_UNEXPECTED;
	}

	auto it = g_clientsMap.find(clientID);

	RAKeyManager& clientKeyMgr = it->second.second;

	sgx_status_t enclaveRes = SGX_SUCCESS;

	uint8_t aes_gcm_iv[SAMPLE_SP_IV_SIZE] = { 0 };
	enclaveRes = sgx_rijndael128GCM_encrypt(&clientKeyMgr.GetSK(),
		reinterpret_cast<const uint8_t*>(&g_cryptoMgr.GetEncrPriKey()),
		sizeof(sgx_ec256_private_t),
		reinterpret_cast<uint8_t*>(outPriKey),
		aes_gcm_iv,
		SAMPLE_SP_IV_SIZE,
		nullptr,
		0,
		outPriKeyMac
	);
	if (enclaveRes != SGX_SUCCESS)
	{
		return enclaveRes;
	}

	enclaveRes = sgx_rijndael128GCM_encrypt(&clientKeyMgr.GetSK(),
		reinterpret_cast<const uint8_t*>(&g_cryptoMgr.GetEncrPubKey()),
		sizeof(sgx_ec256_public_t),
		reinterpret_cast<uint8_t*>(outPubKey),
		aes_gcm_iv,
		SAMPLE_SP_IV_SIZE,
		nullptr,
		0,
		outPubKeyMac
	);

	return enclaveRes;
}

sgx_status_t ecall_set_protocol_sign_key(const char* clientID, const sgx_ec256_private_t* inPriKey, const sgx_aes_gcm_128bit_tag_t* inPriKeyMac, const sgx_ec256_public_t* inPubKey, const sgx_aes_gcm_128bit_tag_t* inPubKeyMac)
{
	if (g_decentMode != DecentNodeMode::ROOT_SERVER)
	{
		return SGX_ERROR_UNEXPECTED;
	}
	if (!IsBothWayAttested(clientID))
	{
		return SGX_ERROR_UNEXPECTED;
	}

	auto it = g_clientsMap.find(clientID);

	RAKeyManager& clientKeyMgr = it->second.second;

	sgx_status_t enclaveRes = SGX_SUCCESS;

	uint8_t aes_gcm_iv[SAMPLE_SP_IV_SIZE] = { 0 };
	sgx_ec256_private_t priKey;
	enclaveRes = sgx_rijndael128GCM_decrypt(&clientKeyMgr.GetSK(),
		reinterpret_cast<const uint8_t*>(inPriKey),
		sizeof(sgx_ec256_private_t),
		reinterpret_cast<uint8_t*>(&priKey),
		aes_gcm_iv,
		SAMPLE_SP_IV_SIZE,
		nullptr,
		0,
		inPriKeyMac
	);
	if (enclaveRes != SGX_SUCCESS)
	{
		return enclaveRes;
	}
	sgx_ec256_public_t pubKey;
	enclaveRes = sgx_rijndael128GCM_decrypt(&clientKeyMgr.GetSK(),
		reinterpret_cast<const uint8_t*>(inPubKey),
		sizeof(sgx_ec256_public_t),
		reinterpret_cast<uint8_t*>(&pubKey),
		aes_gcm_iv,
		SAMPLE_SP_IV_SIZE,
		nullptr,
		0,
		inPubKeyMac
	);
	if (enclaveRes != SGX_SUCCESS)
	{
		return enclaveRes;
	}

	sgx_ec256_signature_t signSign;
	enclaveRes = sgx_ecdsa_sign(reinterpret_cast<const uint8_t*>(&pubKey), sizeof(sgx_ec256_public_t), &priKey, &signSign, g_cryptoMgr.GetECC());
	if (enclaveRes != SGX_SUCCESS)
	{
		return enclaveRes;
	}

	sgx_ec256_signature_t encrSign;
	enclaveRes = sgx_ecdsa_sign(reinterpret_cast<const uint8_t*>(&g_cryptoMgr.GetEncrPubKey()), sizeof(sgx_ec256_public_t), &priKey, &encrSign, g_cryptoMgr.GetECC());
	if (enclaveRes != SGX_SUCCESS)
	{
		return enclaveRes;
	}

	g_cryptoMgr.SetSignPriKey(priKey);
	g_cryptoMgr.SetSignPubKey(pubKey);
	g_cryptoMgr.SetProtoSignPubKey(pubKey);
	g_cryptoMgr.SetSignKeySign(signSign);
	g_cryptoMgr.SetEncrKeySign(encrSign);

	return enclaveRes;
}

sgx_status_t ecall_set_protocol_encr_key(const char* clientID, const sgx_ec256_private_t* inPriKey, const sgx_aes_gcm_128bit_tag_t* inPriKeyMac, const sgx_ec256_public_t* inPubKey, const sgx_aes_gcm_128bit_tag_t* inPubKeyMac)
{
	if (g_decentMode != DecentNodeMode::ROOT_SERVER)
	{
		return SGX_ERROR_UNEXPECTED;
	}
	if (!IsBothWayAttested(clientID))
	{
		return SGX_ERROR_UNEXPECTED;
	}

	auto it = g_clientsMap.find(clientID);

	RAKeyManager& clientKeyMgr = it->second.second;

	sgx_status_t enclaveRes = SGX_SUCCESS;

	uint8_t aes_gcm_iv[SAMPLE_SP_IV_SIZE] = { 0 };
	sgx_ec256_private_t priKey;
	enclaveRes = sgx_rijndael128GCM_decrypt(&clientKeyMgr.GetSK(),
		reinterpret_cast<const uint8_t*>(inPriKey),
		sizeof(sgx_ec256_private_t),
		reinterpret_cast<uint8_t*>(&priKey),
		aes_gcm_iv,
		SAMPLE_SP_IV_SIZE,
		nullptr,
		0,
		inPriKeyMac
	);
	if (enclaveRes != SGX_SUCCESS)
	{
		return enclaveRes;
	}

	sgx_ec256_public_t pubKey;
	enclaveRes = sgx_rijndael128GCM_decrypt(&clientKeyMgr.GetSK(),
		reinterpret_cast<const uint8_t*>(inPubKey),
		sizeof(sgx_ec256_public_t),
		reinterpret_cast<uint8_t*>(&pubKey),
		aes_gcm_iv,
		SAMPLE_SP_IV_SIZE,
		nullptr,
		0,
		inPubKeyMac
	);
	if (enclaveRes != SGX_SUCCESS)
	{
		return enclaveRes;
	}

	sgx_ec256_signature_t encrSign;
	enclaveRes = sgx_ecdsa_sign(reinterpret_cast<const uint8_t*>(&encrSign), sizeof(sgx_ec256_public_t), const_cast<sgx_ec256_private_t*>(&g_cryptoMgr.GetSignPriKey()), &encrSign, g_cryptoMgr.GetECC());
	if (enclaveRes != SGX_SUCCESS)
	{
		return enclaveRes;
	}

	g_cryptoMgr.SetEncrPriKey(priKey);
	g_cryptoMgr.SetEncrPubKey(pubKey);
	g_cryptoMgr.SetEncrKeySign(encrSign);

	return enclaveRes;
}

sgx_status_t ecall_get_protocol_key_signed(const char* clientID, const sgx_ec256_public_t* inSignKey, const sgx_ec256_public_t* inEncrKey,
	sgx_ec256_signature_t* outSignSign, sgx_aes_gcm_128bit_tag_t* outSignSignMac, sgx_ec256_signature_t* outEncrSign, sgx_aes_gcm_128bit_tag_t* outEncrSignMac)
{
	if (g_decentMode != DecentNodeMode::ROOT_SERVER)
	{
		return SGX_ERROR_UNEXPECTED;
	}
	if (!IsBothWayAttested(clientID))
	{
		return SGX_ERROR_UNEXPECTED;
	}

	auto it = g_clientsMap.find(clientID);

	RAKeyManager& clientKeyMgr = it->second.second;

	sgx_status_t enclaveRes = SGX_SUCCESS;
	sgx_ec256_signature_t signSign;
	sgx_ec256_signature_t encrSign;

	enclaveRes = sgx_ecdsa_sign(reinterpret_cast<const uint8_t*>(inSignKey), sizeof(sgx_ec256_public_t), const_cast<sgx_ec256_private_t*>(&g_cryptoMgr.GetEncrPriKey()), &signSign, g_cryptoMgr.GetECC());
	if (enclaveRes != SGX_SUCCESS)
	{
		return enclaveRes;
	}
	enclaveRes = sgx_ecdsa_sign(reinterpret_cast<const uint8_t*>(inEncrKey), sizeof(sgx_ec256_public_t), const_cast<sgx_ec256_private_t*>(&g_cryptoMgr.GetEncrPriKey()), &encrSign, g_cryptoMgr.GetECC());
	if (enclaveRes != SGX_SUCCESS)
	{
		return enclaveRes;
	}

	uint8_t aes_gcm_iv[SAMPLE_SP_IV_SIZE] = { 0 };
	enclaveRes = sgx_rijndael128GCM_encrypt(&clientKeyMgr.GetSK(),
		reinterpret_cast<const uint8_t*>(&signSign),
		sizeof(sgx_ec256_signature_t),
		reinterpret_cast<uint8_t*>(outSignSign),
		aes_gcm_iv,
		SAMPLE_SP_IV_SIZE,
		nullptr,
		0,
		outSignSignMac
	);
	if (enclaveRes != SGX_SUCCESS)
	{
		return enclaveRes;
	}

	enclaveRes = sgx_rijndael128GCM_encrypt(&clientKeyMgr.GetSK(),
		reinterpret_cast<const uint8_t*>(&encrSign),
		sizeof(sgx_ec256_signature_t),
		reinterpret_cast<uint8_t*>(outEncrSign),
		aes_gcm_iv,
		SAMPLE_SP_IV_SIZE,
		nullptr,
		0,
		outEncrSignMac
	);

	return enclaveRes;
}

sgx_status_t ecall_set_key_signs(const char* clientID, const sgx_ec256_signature_t* inSignSign, const sgx_aes_gcm_128bit_tag_t* inSignSignMac, const sgx_ec256_signature_t* inEncrSign, const sgx_aes_gcm_128bit_tag_t* inEncrSignMac)
{
	if (g_decentMode != DecentNodeMode::APPL_SERVER)
	{
		return SGX_ERROR_UNEXPECTED;
	}
	if (!IsBothWayAttested(clientID))
	{
		return SGX_ERROR_UNEXPECTED;
	}

	auto it = g_serversMap.find(clientID);

	RAKeyManager& serverKeyMgr = it->second.second;

	sgx_status_t enclaveRes = SGX_SUCCESS;
	sgx_ec256_signature_t signSign;
	sgx_ec256_signature_t encrSign;

	uint8_t aes_gcm_iv[SAMPLE_SP_IV_SIZE] = { 0 };
	enclaveRes = sgx_rijndael128GCM_decrypt(&serverKeyMgr.GetSK(),
		reinterpret_cast<const uint8_t*>(inSignSign),
		sizeof(sgx_ec256_signature_t),
		reinterpret_cast<uint8_t*>(&signSign),
		aes_gcm_iv,
		SAMPLE_SP_IV_SIZE,
		nullptr,
		0,
		inSignSignMac
	);
	if (enclaveRes != SGX_SUCCESS)
	{
		return enclaveRes;
	}
	enclaveRes = sgx_rijndael128GCM_decrypt(&serverKeyMgr.GetSK(),
		reinterpret_cast<const uint8_t*>(inEncrSign),
		sizeof(sgx_ec256_signature_t),
		reinterpret_cast<uint8_t*>(&encrSign),
		aes_gcm_iv,
		SAMPLE_SP_IV_SIZE,
		nullptr,
		0,
		inEncrSignMac
	);
	if (enclaveRes != SGX_SUCCESS)
	{
		return enclaveRes;
	}

	g_cryptoMgr.SetSignKeySign(signSign);
	g_cryptoMgr.SetEncrKeySign(encrSign);

	g_cryptoMgr.SetProtoSignPubKey(serverKeyMgr.GetSignKey());

	return enclaveRes;
}

void ecall_get_key_signs(sgx_ec256_signature_t* outSignSign, sgx_ec256_signature_t* outEncrSign)
{
	std::memcpy(outSignSign, &g_cryptoMgr.GetSignKeySign(), sizeof(sgx_ec256_signature_t));
	std::memcpy(outEncrSign, &g_cryptoMgr.GetEncrKeySign(), sizeof(sgx_ec256_signature_t));
}

sgx_status_t ecall_proc_decent_msg0(const char* clientID, const sgx_ec256_public_t* inSignKey, const sgx_ec256_signature_t* inSignSign, const sgx_ec256_public_t* inEncrKey, const sgx_ec256_signature_t* inEncrSign)
{
	sgx_status_t enclaveRes = SGX_SUCCESS;

	uint8_t verifyRes = 0;
	enclaveRes = sgx_ecdsa_verify(reinterpret_cast<const uint8_t*>(inSignKey), sizeof(sgx_ec256_public_t), &g_cryptoMgr.GetProtoSignPubKey(), const_cast<sgx_ec256_signature_t*>(inSignSign), &verifyRes, g_cryptoMgr.GetECC());
	if (enclaveRes != SGX_SUCCESS)
	{
		return enclaveRes;
	}
	if (verifyRes != SGX_EC_VALID)
	{
		return SGX_ERROR_UNEXPECTED;
	}

	enclaveRes = sgx_ecdsa_verify(reinterpret_cast<const uint8_t*>(inEncrKey), sizeof(sgx_ec256_public_t), &g_cryptoMgr.GetProtoSignPubKey(), const_cast<sgx_ec256_signature_t*>(inEncrSign), &verifyRes, g_cryptoMgr.GetECC());
	if (enclaveRes != SGX_SUCCESS)
	{
		return enclaveRes;
	}
	if (verifyRes != SGX_EC_VALID)
	{
		return SGX_ERROR_UNEXPECTED;
	}

	g_clientsMap.insert(std::make_pair<std::string, std::pair<ClientRAState, RAKeyManager> >(clientID, std::make_pair<ClientRAState, RAKeyManager>(ClientRAState::ATTESTED, RAKeyManager(*inSignKey))));
	g_serversMap.insert(std::make_pair<std::string, std::pair<ServerRAState, RAKeyManager> >(clientID, std::make_pair<ServerRAState, RAKeyManager>(ServerRAState::ATTESTED, RAKeyManager(*inSignKey))));

	RAKeyManager& svrMgr = g_clientsMap.find(clientID)->second.second;
	RAKeyManager& cliMgr = g_serversMap.find(clientID)->second.second;

	svrMgr.SetEncryptKey(*inEncrKey);
	cliMgr.SetEncryptKey(*inEncrKey);


	sgx_ec256_dh_shared_t sharedKey;
	enclaveRes = sgx_ecc256_compute_shared_dhkey(const_cast<sgx_ec256_private_t*>(&(g_cryptoMgr.GetEncrPriKey())), &(svrMgr.GetEncryptKey()), &sharedKey, g_cryptoMgr.GetECC());
	if (enclaveRes != SGX_SUCCESS)
	{
		DropClientRAState(clientID);
		DropServerRAState(clientID);
		return enclaveRes;
	}
	svrMgr.SetSharedKey(sharedKey);
	cliMgr.SetSharedKey(sharedKey);

	sgx_ec_key_128bit_t tmpDerivedKey;
	bool keyDeriveRes = false;
	keyDeriveRes = derive_key(&(svrMgr.GetSharedKey()), SAMPLE_DERIVE_KEY_SMK, &tmpDerivedKey);
	if (!keyDeriveRes)
	{
		DropClientRAState(clientID);
		DropServerRAState(clientID);
		return SGX_ERROR_UNEXPECTED;
	}
	svrMgr.SetSMK(tmpDerivedKey);
	cliMgr.SetSMK(tmpDerivedKey);

	keyDeriveRes = derive_key(&(svrMgr.GetSharedKey()), SAMPLE_DERIVE_KEY_SK, &tmpDerivedKey);
	if (!keyDeriveRes)
	{
		DropClientRAState(clientID);
		DropServerRAState(clientID);
		return SGX_ERROR_UNEXPECTED;
	}
	svrMgr.SetSK(tmpDerivedKey);
	cliMgr.SetSK(tmpDerivedKey);

	keyDeriveRes = derive_key(&(svrMgr.GetSharedKey()), SAMPLE_DERIVE_KEY_MK, &tmpDerivedKey);
	if (!keyDeriveRes)
	{
		DropClientRAState(clientID);
		DropServerRAState(clientID);
		return SGX_ERROR_UNEXPECTED;
	}
	svrMgr.SetMK(tmpDerivedKey);
	cliMgr.SetMK(tmpDerivedKey);

	keyDeriveRes = derive_key(&(svrMgr.GetSharedKey()), SAMPLE_DERIVE_KEY_VK, &tmpDerivedKey);
	if (!keyDeriveRes)
	{
		DropClientRAState(clientID);
		DropServerRAState(clientID);
		return SGX_ERROR_UNEXPECTED;
	}
	svrMgr.SetVK(tmpDerivedKey);
	cliMgr.SetVK(tmpDerivedKey);

	return enclaveRes;
}

sgx_status_t ecall_get_simple_secret(const char* clientID, uint64_t* secret, sgx_aes_gcm_128bit_tag_t* outSecretMac)
{
	sgx_status_t enclaveRes = SGX_SUCCESS;

	static uint64_t simple_secret = 1234567;

	if (g_decentMode != DecentNodeMode::APPL_SERVER)
	{
		return SGX_ERROR_UNEXPECTED;
	}
	if (!IsBothWayAttested(clientID))
	{
		return SGX_ERROR_UNEXPECTED;
	}

	auto it = g_serversMap.find(clientID);

	RAKeyManager& serverKeyMgr = it->second.second;

	uint8_t aes_gcm_iv[SAMPLE_SP_IV_SIZE] = { 0 };
	enclaveRes = sgx_rijndael128GCM_encrypt(&serverKeyMgr.GetSK(),
		reinterpret_cast<const uint8_t*>(&simple_secret),
		sizeof(uint64_t),
		reinterpret_cast<uint8_t*>(secret),
		aes_gcm_iv,
		SAMPLE_SP_IV_SIZE,
		nullptr,
		0,
		outSecretMac
	);

	enclave_printf("Encrypted a simple secret: %llu\n", simple_secret);

	return enclaveRes;
}

sgx_status_t ecall_proc_simple_secret(const char* clientID, const uint64_t* secret, const sgx_aes_gcm_128bit_tag_t* inSecretMac)
{
	sgx_status_t enclaveRes = SGX_SUCCESS;

	if (g_decentMode != DecentNodeMode::APPL_SERVER)
	{
		return SGX_ERROR_UNEXPECTED;
	}
	if (!IsBothWayAttested(clientID))
	{
		return SGX_ERROR_UNEXPECTED;
	}

	auto it = g_serversMap.find(clientID);

	RAKeyManager& serverKeyMgr = it->second.second;
	uint64_t simple_secret = 0;

	uint8_t aes_gcm_iv[SAMPLE_SP_IV_SIZE] = { 0 };
	enclaveRes = sgx_rijndael128GCM_decrypt(&serverKeyMgr.GetSK(),
		reinterpret_cast<const uint8_t*>(secret),
		sizeof(uint64_t),
		reinterpret_cast<uint8_t*>(&simple_secret),
		aes_gcm_iv,
		SAMPLE_SP_IV_SIZE,
		nullptr,
		0,
		inSecretMac
	);

	enclave_printf("Decrypted a simple secret: %llu\n", simple_secret);

	return enclaveRes;
}
