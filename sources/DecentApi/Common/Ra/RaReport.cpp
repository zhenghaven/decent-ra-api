#include "RaReport.h"

#ifdef ENCLAVE_ENVIRONMENT
#include <rapidjson/document.h>
#else
#include <json/json.h>
#endif

#include "../consttime_memequal.h"
#include "../Common.h"
#include "../GeneralKeyTypes.h"

#include "../Net/CommonMessages.h"

#include "../Tools/DataCoding.h"
#include "../Tools/JsonTools.h"

#include "../SGX/IasReport.h"
#include "../SGX/sgx_structs.h" /*TODO: remove this dependency.*/

using namespace Decent::Ra;
using namespace Decent::Tools;

bool RaReport::ProcessSelfRaReport(const std::string & platformType,
	const std::string & pubKeyPem, const std::string & raReport,
	std::string & outHashStr, report_timestamp_t& outTimestamp)
{
	if (platformType == sk_ValueReportTypeSgx)
	{
		sgx_ias_report_t outIasReport;
		bool verifyRes = ProcessSgxSelfRaReport(pubKeyPem, raReport, outIasReport);

		outTimestamp = outIasReport.m_timestamp;

		outHashStr = SerializeStruct(outIasReport.m_quote.report_body.mr_enclave);

		return verifyRes;
	}

	throw RuntimeException("Process Self-RA Report failed: Unrecognized enclave platform.");
}

bool RaReport::ProcessSgxSelfRaReport(const std::string& pubKeyPem, const std::string & raReport, sgx_ias_report_t & outIasReport)
{
	using namespace Decent::Net;
	if (raReport.size() == 0)
	{
		return false;
	}

	JsonDoc jsonDoc;
	ParseStr2Json(jsonDoc, raReport);

	if (!jsonDoc.JSON_HAS_MEMBER(RaReport::sk_LabelRoot) || !jsonDoc[RaReport::sk_LabelRoot].JSON_IS_OBJECT())
	{
		throw RuntimeException("Process SGX Self-RA Report failed: invalid JSON format.");
	}
	JsonValue& jsonRoot = jsonDoc[RaReport::sk_LabelRoot];

	std::string iasReportStr = CommonJsonMsg::ParseValue<std::string>(jsonRoot, RaReport::sk_LabelIasReport);
	std::string iasSign = CommonJsonMsg::ParseValue<std::string>(jsonRoot, RaReport::sk_LabelIasSign);
	std::string iasCertChain = CommonJsonMsg::ParseValue<std::string>(jsonRoot, RaReport::sk_LabelIasCertChain);
	std::string oriRDB64 = CommonJsonMsg::ParseValue<std::string>(jsonRoot, RaReport::sk_LabelOriRepData);

	sgx_report_data_t oriReportData;
	DeserializeStruct(oriReportData, oriRDB64);

	auto quoteVerifier = [&pubKeyPem, &oriReportData](const sgx_ias_report_t & iasReport) -> bool
	{
		using namespace mbedTLScpp;

		return DecentReportDataVerifier(pubKeyPem,
			CtnFullR(oriReportData.d),
			CtnFullR(iasReport.m_quote.report_body.report_data.d));
	};

	bool reportVerifyRes = Decent::Ias::ParseAndVerifyIasReport(outIasReport, iasReportStr, iasCertChain, iasSign, nullptr, sk_sgxDecentRaConfig, quoteVerifier);

	return reportVerifyRes;
}
