#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <memory>

#include <sgx_error.h>

#include "../../common/GeneralKeyTypes.h"

#include <functional>
#include <vector>
typedef std::function<bool(const uint8_t* initData, const std::vector<uint8_t>& inData)> ReportDataVerifier;


typedef struct _ra_msg1_t sgx_ra_msg1_t;
typedef struct _ra_msg2_t sgx_ra_msg2_t;
typedef struct _sgx_ec256_signature_t sgx_ec256_signature_t;
typedef struct _sgx_ec256_public_t sgx_ec256_public_t;
typedef struct _sgx_report_data_t sgx_report_data_t;
typedef struct _spid_t sgx_spid_t;
typedef uint32_t sgx_ra_context_t;

typedef struct _ias_report_t sgx_ias_report_t;

class AESGCMCommLayer;

namespace SGXRAEnclave
{
	bool SetReportDataVerifier(const std::string& clientID, ReportDataVerifier func);
	void DropClientRAState(const std::string& clientID);
	bool IsClientAttested(const std::string& clientID);
	bool ReleaseClientKeys(const std::string& clientID, std::unique_ptr<sgx_ias_report_t>& outIasReport, std::unique_ptr<sgx_ec256_public_t>& outSignPubKey, std::unique_ptr<GeneralAES128BitKey>& outSK, std::unique_ptr<GeneralAES128BitKey>& outMK);
	AESGCMCommLayer* ReleaseClientKeys(const std::string& clientID, std::unique_ptr<sgx_ias_report_t>& outIasReport);
	void SetSPID(const sgx_spid_t& spid);
	bool VerifyIASReport(sgx_ias_report_t& outIasReport, const std::string& iasReportStr, const std::string& reportCert, const std::string& reportSign, const sgx_report_data_t& oriRD, ReportDataVerifier rdVerifier, const char* nonce);

	sgx_status_t ServiceProviderInit();
	void ServiceProviderTerminate();
	sgx_status_t GetIasNonce(const std::string& clientId, char* outStr);
	sgx_status_t GetRASPSignPubKey(sgx_ec256_public_t& outKey);
	sgx_status_t ProcessRaMsg1(const std::string& clientId, const sgx_ec256_public_t& inKey, const sgx_ra_msg1_t& inMsg1, sgx_ra_msg2_t& outMsg2);
	sgx_status_t ProcessRaMsg3(const std::string& clientId, const uint8_t* inMsg3, uint32_t msg3Len, const std::string& iasReport, const std::string& reportSign, const std::string& reportCert, sgx_ias_report_t& outMsg4, sgx_ec256_signature_t& outMsg4Sign, sgx_report_data_t* outOriRD = nullptr);
}
