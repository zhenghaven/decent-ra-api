#include "RaReport.h"

#ifdef ENCLAVE_ENVIRONMENT
#include <rapidjson/document.h>
#else
#include <json/json.h>
#endif

#include "../consttime_memequal.h"
#include "../Common.h"

#include "../Tools/DataCoding.h"
#include "../Tools/JsonTools.h"
#include "../MbedTls/MbedTlsHelpers.h"
#include "../SGX/IasReport.h"
#include "../SGX/sgx_structs.h" /*TODO: remove this dependency.*/

#include "Crypto.h"

using namespace Decent;
using namespace Decent::Ra;
using namespace Decent::Tools;

namespace
{
	static constexpr uint32_t sk_sec2MicroSec = 1000000;
	static constexpr uint32_t sk_microSec2NanoSec = 1000;
}

bool RaReport::DecentReportDataVerifier(const std::string & pubSignKey, const uint8_t* initData, const uint8_t* expected, const size_t size)
{
	if (size != GENERAL_256BIT_32BYTE_SIZE ||
		pubSignKey.size() == 0 )
	{
		return false;
	}

	General256Hash hashRes;
	MbedTlsHelper::CalcHashSha256(MbedTlsHelper::hashListMode, 
		{
			{initData, size},
			{pubSignKey.data(), pubSignKey.size()},
		}, hashRes);

	return consttime_memequal(expected, hashRes.data(), hashRes.size()) == 1;
}

bool RaReport::ProcessSelfRaReport(const std::string & platformType, const std::string & pubKeyPem, const std::string & raReport, std::string & outHashStr, TimeStamp& outTimestamp)
{
	if (platformType == sk_ValueReportTypeSgx)
	{
		sgx_ias_report_t outIasReport;
		bool verifyRes = ProcessSgxSelfRaReport(pubKeyPem, raReport, outIasReport);
		outTimestamp.m_year = outIasReport.m_timestamp.m_year;
		outTimestamp.m_month = outIasReport.m_timestamp.m_month;
		outTimestamp.m_day = outIasReport.m_timestamp.m_day;

		outTimestamp.m_hour = outIasReport.m_timestamp.m_hour;
		outTimestamp.m_min = outIasReport.m_timestamp.m_min;
		outTimestamp.m_sec = static_cast<uint8_t>(outIasReport.m_timestamp.m_sec);
		//TODO: Fix time precision later.
		outTimestamp.m_nanoSec = static_cast<uint32_t>((outIasReport.m_timestamp.m_sec - outTimestamp.m_sec) * sk_sec2MicroSec) * sk_microSec2NanoSec;

		outHashStr = SerializeStruct(outIasReport.m_quote.report_body.mr_enclave);

		return verifyRes;
	}
	return false;
}

bool RaReport::ProcessSgxSelfRaReport(const std::string& pubKeyPem, const std::string & raReport, sgx_ias_report_t & outIasReport)
{
	if (raReport.size() == 0)
	{
		return false;
	}

	JsonDoc jsonDoc;

	if (!ParseStr2Json(jsonDoc, raReport) ||
		!jsonDoc.JSON_HAS_MEMBER(RaReport::sk_LabelRoot))
	{
		return false;
	}
	JsonValue& jsonRoot = jsonDoc[RaReport::sk_LabelRoot];

	std::string iasReportStr = jsonRoot[RaReport::sk_LabelIasReport].JSON_AS_STRING();
	std::string iasSign = jsonRoot[RaReport::sk_LabelIasSign].JSON_AS_STRING();
	std::string iasCertChain = jsonRoot[RaReport::sk_LabelIasCertChain].JSON_AS_STRING();
	std::string oriRDB64 = jsonRoot[RaReport::sk_LabelOriRepData].JSON_AS_STRING();

	sgx_report_data_t oriReportData;
	DeserializeStruct(oriReportData, oriRDB64);

	auto quoteVerifier = [&pubKeyPem, &oriReportData](const sgx_ias_report_t & iasReport) -> bool
	{
		return DecentReportDataVerifier(pubKeyPem, oriReportData.d, iasReport.m_quote.report_body.report_data.d, 
			sizeof(sgx_report_data_t) / 2);
	};

	bool reportVerifyRes = Decent::Ias::ParseAndVerifyIasReport(outIasReport, iasReportStr, iasCertChain, iasSign, nullptr, sk_sgxDecentRaConfig, quoteVerifier);

	return reportVerifyRes;
}
