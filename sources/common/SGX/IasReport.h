#pragma once

#include <cstdint>

#include <string>

typedef struct _sgx_ias_report_t sgx_ias_report_t;

enum class ias_quote_status_t : uint8_t {
	IAS_QUOTE_OK                          = 0,
	IAS_QUOTE_SIGNATURE_INVALID           = 1,
	IAS_QUOTE_GROUP_REVOKED               = 2,
	IAS_QUOTE_SIGNATURE_REVOKED           = 3,
	IAS_QUOTE_KEY_REVOKED                 = 4,
	IAS_QUOTE_SIGRL_VERSION_MISMATCH      = 5,
	IAS_QUOTE_GROUP_OUT_OF_DATE           = 6,
};

// Revocation Reasons from RFC5280
enum ias_revoc_reason_t : uint8_t {
	IAS_REVOC_REASON_UNSPECIFIED              = 0,//RFC5280 - 0
	IAS_REVOC_REASON_KEY_COMPROMISE           = 1,//RFC5280 - 1
	IAS_REVOC_REASON_CA_COMPROMISED           = 2,//RFC5280 - 2
	IAS_REVOC_REASON_AFFILIATION_CHANGED      = 3, //RFC5280 - 3
	IAS_REVOC_REASON_SUPERCEDED               = 4, //RFC5280 - 4
	IAS_REVOC_REASON_CESSATION_OF_OPERATION   = 5, //RFC5280 - 5
	IAS_REVOC_REASON_CERTIFICATE_HOLD         = 6, //RFC5280 - 6
	IAS_REVOC_REASON_REMOVE_FROM_CRL          = 8, //RFC5280 - 8
	IAS_REVOC_REASON_PRIVILEGE_WITHDRAWN      = 9, //RFC5280 - 9
	IAS_REVOC_REASON_AA_COMPROMISE            = 10, //RFC5280 - 10
};

enum ias_pse_status_t : uint8_t{
	IAS_PSE_NA                       = 0,
	IAS_PSE_OK                       = 1,
	IAS_PSE_UNKNOWN                  = 2,
	IAS_PSE_INVALID                  = 3,
	IAS_PSE_OUT_OF_DATE              = 4,
	IAS_PSE_REVOKED                  = 5,
	IAS_PSE_RL_VERSION_MISMATCH      = 6,
};
	
bool ParseIasReport(sgx_ias_report_t& outReport, std::string& outId, std::string& outNonce, const std::string& inStr);

//This function only checks report & PSE status (and report nonce).
bool ParseAndCheckIasReport(sgx_ias_report_t& outIasReport,
	const std::string& iasReportStr, const std::string& reportCert, const std::string& reportSign,
	const char* nonce);

//User provides verifier to verify the report.
template<typename Vrfier>
bool ParseAndVerifyIasReport(sgx_ias_report_t& outIasReport,
	const std::string& iasReportStr, const std::string& reportCert, const std::string& reportSign,
	const char* nonce, Vrfier vrfier)
{
	const sgx_ias_report_t& iasReport = outIasReport;
	return ParseAndCheckIasReport(outIasReport, iasReportStr, reportCert, reportSign, nonce) &&
		vrfier(iasReport);
}
