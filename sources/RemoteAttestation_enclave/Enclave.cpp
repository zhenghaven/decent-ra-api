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

#include "../common/CryptoTools.h"
#include "../common/sgx_ra_msg4.h"

namespace 
{
	sgx_spid_t sgxSPID = { "Decent X" };

	sgx_ec256_private_t* sgxRAPriKey = nullptr;
	sgx_ec256_public_t* sgxRAPubkey = nullptr;

	sgx_ecc_state_handle_t g_eccContext = nullptr;
	//RAKeyManager* g_serverKeyMgr = nullptr;
	std::map<std::string, std::pair<ServerRAState, RAKeyManager> > g_serversMap;
	std::map<std::string, std::pair<ClientRAState, RAKeyManager> > g_clientsMap;
}

static void CleanRAKeys()
{
	delete sgxRAPriKey;
	sgxRAPriKey = nullptr;

	delete sgxRAPubkey;
	sgxRAPubkey = nullptr;
}

inline bool IsRAKeyExist()
{
	return (!sgxRAPriKey || !sgxRAPubkey);
}

sgx_status_t ecall_generate_ra_keys()
{
	sgx_status_t res = SGX_SUCCESS;

	if (!g_eccContext)
	{
		//Context is empty, need to create a new one.
		res = sgx_ecc256_open_context(&g_eccContext);
	}
	
	//Context is not empty at this point.
	if (res != SGX_SUCCESS)
	{
		//Context generation failed, clean the memory, return the result.
		CleanRAKeys();
		return res;
	}

	if (!sgxRAPriKey || !sgxRAPubkey)
	{
		//Key pairs are empty, need to generate new pair
		sgxRAPriKey = new sgx_ec256_private_t;
		sgxRAPubkey = new sgx_ec256_public_t;
		if (!sgxRAPriKey || !sgxRAPubkey)
		{
			//memory allocation failed, clean the memory, return the result.
			CleanRAKeys();
			return SGX_ERROR_OUT_OF_MEMORY;
		}
		else
		{
			//memory allocation success, try to create new key pair.
			res = sgx_ecc256_create_key_pair(sgxRAPriKey, sgxRAPubkey, g_eccContext);
		}
	}
	
	if (res != SGX_SUCCESS)
	{
		//Key pair generation failed, clean the memory.
		CleanRAKeys();
	}

	return res;
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
	res = ecall_generate_ra_keys();

	if (res != SGX_SUCCESS)
	{
		return res;
	}
	memcpy(outKey, sgxRAPubkey, sizeof(sgx_ec256_public_t));
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

	std::string raPubKeyStr;
	res = ecall_generate_ra_keys();
	raPubKeyStr = SerializePubKey(*sgxRAPubkey);
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
	res = sgx_ecc256_compute_shared_dhkey(sgxRAPriKey, &(clientKeyMgr.GetEncryptKey()), &sharedKey, g_eccContext);
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

	memcpy(&(outMsg2->g_b), sgxRAPubkey, sizeof(sgx_ec256_public_t));
	memcpy(&(outMsg2->spid), &sgxSPID, sizeof(sgxSPID));
	outMsg2->quote_type = SGX_QUOTE_LINKABLE_SIGNATURE;

	outMsg2->kdf_id = SAMPLE_AES_CMAC_KDF_ID;

	sgx_ec256_public_t gb_ga[2];
	memcpy(&gb_ga[0], sgxRAPubkey, sizeof(sgx_ec256_public_t));
	memcpy(&gb_ga[1], &(clientKeyMgr.GetEncryptKey()), sizeof(sgx_ec256_public_t));

	res = sgx_ecdsa_sign((uint8_t *)&gb_ga, sizeof(gb_ga), sgxRAPriKey, &(outMsg2->sign_gb_ga), g_eccContext);
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
	res = sgx_ra_get_keys(inContextID, SGX_RA_KEY_VK, &tmpKey);
	if (res != SGX_SUCCESS)
	{
		return res;
	}
	serverKeyMgr.SetVK(tmpKey);

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
	enclave_printf("In Proc Msg 3, bp1\n");

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

	res = sgx_sha256_update(reinterpret_cast<const uint8_t*>(sgxRAPubkey), sizeof(sgx_ec256_public_t), sha_handle);
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

	res = sgx_ecdsa_sign((uint8_t *)outMsg4, sizeof(sgx_ra_msg4_t), sgxRAPriKey, outMsg4Sign, g_eccContext);
	if (res != SGX_SUCCESS)
	{
		DropClientRAState(clientID);
		return res;
	}

	it->second.first = ClientRAState::ATTESTED;

	return res;
}

sgx_status_t ecall_process_ra_msg4(const char* ServerID, const sgx_ra_msg4_t* inMsg4, sgx_ec256_signature_t* inMsg4Sign)
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
	res = sgx_ecdsa_verify((uint8_t *)inMsg4, sizeof(sgx_ra_msg4_t), &(serverKeyMgr.GetSignKey()), inMsg4Sign, &signVerifyRes, g_eccContext);
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

	return res;
}

sgx_status_t ecall_termination_clean()
{
	CleanRAKeys();

	if (!g_eccContext)
	{
		sgx_ecc256_close_context(g_eccContext);
		g_eccContext = nullptr;
	}

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
