#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <memory>
#include <functional>
#include <vector>

#include <sgx_error.h>

#include "../../common/GeneralKeyTypes.h"

typedef struct _ra_msg1_t sgx_ra_msg1_t;
typedef struct _ra_msg2_t sgx_ra_msg2_t;
typedef struct _sgx_ec256_signature_t sgx_ec256_signature_t;
typedef struct _sgx_ec256_public_t sgx_ec256_public_t;
typedef struct _sgx_report_data_t sgx_report_data_t;
typedef struct _spid_t sgx_spid_t;
typedef uint32_t sgx_ra_context_t;

typedef struct _sgx_ias_report_t sgx_ias_report_t;

class AESGCMCommLayer;

typedef std::function<bool(const sgx_report_data_t& initData, const sgx_report_data_t& expected)> SgxReportDataVerifier;

namespace SGXRAEnclave
{
	bool SetReportDataVerifier(const std::string& clientID, SgxReportDataVerifier func);
	void DropClientRAState(const std::string& clientID);
	bool IsClientAttested(const std::string& clientID);
	bool ReleaseClientKeys(const std::string& clientID, std::unique_ptr<sgx_ias_report_t>& outIasReport, std::unique_ptr<General128BitKey>& outSK, std::unique_ptr<General128BitKey>& outMK);
	AESGCMCommLayer* ReleaseClientKeys(const std::string& clientID, std::unique_ptr<sgx_ias_report_t>& outIasReport);
	void SetSPID(const sgx_spid_t& spid);
	bool VerifyIASReport(sgx_ias_report_t& outIasReport, const std::string& iasReportStr, const std::string& reportCert, const std::string& reportSign, const sgx_report_data_t& oriRD, SgxReportDataVerifier rdVerifier, const char* nonce);

	sgx_status_t ServiceProviderInit();
	void ServiceProviderTerminate();
	sgx_status_t GetIasNonce(const std::string& clientId, char* outStr);
	sgx_status_t GetRASPSignPubKey(sgx_ec256_public_t& outKey);
	sgx_status_t ProcessRaMsg1(const std::string& clientId, const sgx_ec256_public_t& inKey, const sgx_ra_msg1_t& inMsg1, sgx_ra_msg2_t& outMsg2);
	sgx_status_t ProcessRaMsg3(const std::string& clientId, const uint8_t* inMsg3, uint32_t msg3Len, const std::string& iasReport, const std::string& reportSign, const std::string& reportCert, sgx_ias_report_t& outMsg4, sgx_ec256_signature_t& outMsg4Sign, sgx_report_data_t* outOriRD = nullptr);
}
