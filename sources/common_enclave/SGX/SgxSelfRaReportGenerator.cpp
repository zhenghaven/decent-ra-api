#include "SgxSelfRaReportGenerator.h"

#include <rapidjson/document.h>

#include <sgx_key_exchange.h>

#include "../../common/JsonTools.h"
#include "../../common/DataCoding.h"
#include "../../common/Decent/RaReport.h"
#include "../../common/SGX/sgx_structs.h"
#include "../../common/SGX/SgxRaProcessorSp.h"
#include "SgxDecentRaProcessor.h"

SgxSelfRaReportGenerator::SgxSelfRaReportGenerator(std::unique_ptr<SgxRaProcessorSp>& raSp, std::unique_ptr<SgxDecentRaProcessorClient>& raClient) :
	m_raSp(std::move(raSp)),
	m_raClient(std::move(raClient))
{
}

SgxSelfRaReportGenerator::~SgxSelfRaReportGenerator()
{
}

bool SgxSelfRaReportGenerator::GenerateSelfRaReport(std::string & platformType, std::string & selfRaReport)
{
	if (!m_raSp || !m_raClient)
	{
		return false;
	}
	
	sgx_ra_msg0r_t msg0r;
	sgx_ra_msg1_t msg1;
	std::vector<uint8_t> msg2;
	std::vector<uint8_t> msg3;
	sgx_ra_msg4_t msg4;

	sgx_report_data_t reportData;

	if (!m_raSp->Init() ||
		!m_raSp->GetMsg0r(msg0r) ||
		!m_raClient->ProcessMsg0r(msg0r, msg1) ||
		!m_raSp->ProcessMsg1(msg1, msg2) ||
		!m_raClient->ProcessMsg2(*reinterpret_cast<sgx_ra_msg2_t*>(msg2.data()), msg2.size(), msg3) ||
		!m_raSp->ProcessMsg3(*reinterpret_cast<sgx_ra_msg3_t*>(msg3.data()), msg3.size(), msg4, &reportData))
	{
		return false;
	}

	platformType = Decent::RaReport::sk_ValueReportTypeSgx;

	JSON_EDITION::JSON_DOCUMENT_TYPE jsonDoc;
	JSON_EDITION::Value report;
	JsonCommonSetString(jsonDoc, report, Decent::RaReport::sk_LabelIasReport, m_raSp->GetIasReportStr());
	JsonCommonSetString(jsonDoc, report, Decent::RaReport::sk_LabelIasSign, m_raSp->GetIasReportSign());
	JsonCommonSetString(jsonDoc, report, Decent::RaReport::sk_LabelIasCertChain, m_raSp->GetIasReportCert());
	JsonCommonSetString(jsonDoc, report, Decent::RaReport::sk_LabelOriRepData, SerializeStruct(reportData));

	JSON_EDITION::Value root;
	JsonCommonSetObject(jsonDoc, root, Decent::RaReport::sk_LabelRoot, report);

	selfRaReport = Json2StyleString(root);

	return true;
}
