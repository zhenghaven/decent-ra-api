#pragma once

#include <string>
#include <utility>

#include <sgx_error.h>

typedef struct _ra_msg1_t sgx_ra_msg1_t;
typedef struct _ra_msg2_t sgx_ra_msg2_t;
typedef struct _ra_msg4_t sgx_ra_msg4_t;
typedef struct _sgx_ec256_signature_t sgx_ec256_signature_t;
typedef struct _sgx_ec256_public_t sgx_ec256_public_t;
typedef struct _spid_t sgx_spid_t;
typedef uint32_t sgx_ra_context_t;

namespace SGXRAEnclave
{
	void DropClientRAState(const std::string& clientID);
	bool IsClientAttested(const std::string& clientID);
	void SetTargetEnclaveHash(const std::string& hashBase64);
	void SetSPID(const sgx_spid_t& spid);

	sgx_status_t InitRaSpEnvironment();
	sgx_status_t GetIasNonce(const char* clientID, char* outStr);
	sgx_status_t GetRASPEncrPubKey(sgx_ra_context_t context, sgx_ec256_public_t* outKey);
	sgx_status_t GetRASPSignPubKey(sgx_ec256_public_t* outKey);
	sgx_status_t ProcessRaMsg0Send(const char* clientID);
	sgx_status_t ProcessRaMsg1(const char* clientID, const sgx_ra_msg1_t *inMsg1, sgx_ra_msg2_t *outMsg2);
	sgx_status_t ProcessRaMsg3(const char* clientID, const uint8_t* inMsg3, uint32_t msg3Len, const char* iasReport, const char* reportSign, const char* reportCert, sgx_ra_msg4_t* outMsg4, sgx_ec256_signature_t* outMsg4Sign);
}
