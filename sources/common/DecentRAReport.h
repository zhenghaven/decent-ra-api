#pragma once

#include <cstdint>

#include <string>
#include <vector>

typedef struct _sgx_ias_report_t sgx_ias_report_t;
typedef struct _sgx_measurement_t sgx_measurement_t;

namespace Decent
{
	namespace RAReport
	{
		constexpr char const sk_LabelRoot[]           = "DecentSelfRAReport";

		constexpr char const sk_LabelIasReport[]      = "IASReport";
		constexpr char const sk_LabelIasSign[]        = "IASSignature";
		constexpr char const sk_LabelIasCertChain[]   = "IASCertChain";
		constexpr char const sk_LabelOriRepData[]     = "OriReportData";

		constexpr char const sk_ValueReportTypeSgx[]     = "SGX";


		bool DecentReportDataVerifier(const std::string& pubSignKey, const uint8_t* initData, const uint8_t* expected, const size_t size);

		bool ProcessSelfRaReport(const std::string& platformType, const std::string& pubKeyPem, const std::string& raReport, const std::string& inHashStr, sgx_ias_report_t& outIasReport);
		
		bool ProcessSgxSelfRaReport(const std::string& pubKeyPem, const std::string& raReport, const std::string& inHashStr, sgx_ias_report_t& outIasReport);
	}
}
