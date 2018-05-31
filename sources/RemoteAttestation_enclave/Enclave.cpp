#include <initializer_list>
#include <vector>

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
#include "../common/CryptoTools.h"

namespace 
{
	sgx_ec256_private_t* sgxRAPriKey = nullptr;
	sgx_ec256_public_t* sgxRAPubkey = nullptr;
	sgx_ecc_state_handle_t sgxRAECCContext = nullptr;

	sgx_ec256_public_t* sgxSPRAPubkey = nullptr;
}

static void CleanRAKeys()
{
	if (!sgxRAECCContext)
	{
		sgx_ecc256_close_context(sgxRAECCContext);
		sgxRAECCContext = nullptr;
	}
	if (!sgxRAPriKey)
	{
		delete sgxRAPriKey;
		sgxRAPriKey = nullptr;
	}
	if (!sgxRAPubkey)
	{
		delete sgxRAPubkey;
		sgxRAPubkey = nullptr;
	}
}

static void TerminationCleaning()
{
	CleanRAKeys();

	if (!sgxSPRAPubkey)
	{
		delete sgxSPRAPubkey;
		sgxSPRAPubkey = nullptr;
	}
}

inline bool IsRAKeyExist()
{
	return (!sgxRAPriKey || !sgxRAPubkey);
}

//Feature name        : Initializer lists
//Feature description : An object of type std::initializer_list<T> is a lightweight proxy object that provides access to an array of objects of type const T.
//Demo description    : Demonstrates the usage of initializer list in the constructor of an object in enclave.
class Number
{
public:
	Number(const std::initializer_list<int> &v) {
		for (auto i : v) {
			elements.push_back(i);
		}
	}

	void print_elements() {
		enclave_printf("[initializer_list] The elements of the vector are:");
		for (auto item : elements) {
			enclave_printf(" %d", item);
		}
		enclave_printf(".\n");
	}
private:
	std::vector<int> elements;
};

void ecall_initializer_list_demo()
{
	enclave_printf("[initializer_list] Using initializer list in the constructor. \n");
	Number m = { 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 };
	m.print_elements();

	enclave_printf("\n"); //end of demo
}

int ecall_add_two_int(int a, int b)
{
	int res = a + b;

	enclave_printf("Added %d, %d inside enclave as result of %d\n", a, b, res);

	return res;
}

void ecall_square_array(int* arr, const size_t len_in_byte)
{
	size_t len = len_in_byte / sizeof(int);
	for (int i = 0; i < len; ++i)
	{
		arr[i] *= arr[i];
	}

	std::string base64TestStr = "Base64 test string.";
	std::string base64CodeStr = cppcodec::base64_rfc4648::encode(base64TestStr.c_str(), base64TestStr.size());
	enclave_printf("base 64 code string: %s\n", base64CodeStr.c_str());
	auto base64out = cppcodec::base64_rfc4648::decode(base64CodeStr); ;
	enclave_printf("base 64 code string: %s\n", std::string((char*)base64out.data(), base64out.size()).c_str());

	const char* json = "{\"project\":\"rapidjson\",\"stars\":10}";
	rapidjson::Document d;
	d.Parse(json);
	rapidjson::Value& s = d["stars"];
	s.SetInt(s.GetInt() + 1);

	rapidjson::StringBuffer buffer;
	rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
	d.Accept(writer);

	enclave_printf("JSON Example: %s\n", buffer.GetString());

	std::string raPubKeyStr;
	ecall_generate_ra_keys();
	raPubKeyStr = SerializePubKey(*sgxRAPubkey);
	enclave_printf("Public key string: %s\n", raPubKeyStr.c_str());
	//raPubKeyStr = SerializePubKey(sgxRAPubkey);
	//enclave_printf("Public key string: %s\n", raPubKeyStr.c_str());
	//raPubKeyStr = SerializePubKey(sgxRAPubkey);
	//enclave_printf("Public key string: %s\n", raPubKeyStr.c_str());
	//enclave_printf("Public key size: %d\n", sizeof(sgx_ec256_public_t));

	//CleanRAKeys();
}

sgx_status_t ecall_generate_ra_keys()
{
	sgx_status_t res = SGX_SUCCESS;

	if (!sgxRAECCContext) 
	{
		//Context is empty, need to create a new one.
		res = sgx_ecc256_open_context(&sgxRAECCContext);
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
			res = sgx_ecc256_create_key_pair(sgxRAPriKey, sgxRAPubkey, sgxRAECCContext);
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

sgx_status_t ecall_get_ra_pub_keys(sgx_ec256_public_t* outPubKey)
{
	sgx_status_t res = SGX_SUCCESS;
	res = ecall_generate_ra_keys();

	if (res != SGX_SUCCESS)
	{
		return res;
	}
	memcpy(outPubKey, sgxRAPubkey, sizeof(sgx_ec256_public_t));
	return res;
}

void ecall_set_sp_ra_pub_keys(sgx_ec256_public_t* inPubKey)
{
	if (!sgxSPRAPubkey)
	{
		sgxSPRAPubkey = new sgx_ec256_public_t;
	}
	memcpy(sgxSPRAPubkey, inPubKey, sizeof(sgx_ec256_public_t));
}

sgx_status_t ecall_enclave_init_ra(int b_pse, sgx_ra_context_t *p_context)
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
	ret = sgx_ra_init(sgxSPRAPubkey, b_pse, p_context);
	enclave_printf("RA ContextID: %d\n", *p_context);
	if (b_pse)
	{
		sgx_close_pse_session();
	}
	return ret;
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