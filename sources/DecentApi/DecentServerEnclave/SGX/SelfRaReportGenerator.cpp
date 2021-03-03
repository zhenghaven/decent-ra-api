#include "SelfRaReportGenerator.h"

#include <rapidjson/document.h>

#include <sgx_key_exchange.h>

#include "../../Common/Common.h"
#include "../../Common/Exceptions.h"
#include "../../Common/Tools/JsonTools.h"
#include "../../Common/Tools/DataCoding.h"
#include "../../Common/Ra/RaReport.h"
#include "../../Common/SGX/sgx_structs.h"
#include "../../Common/SGX/RaProcessorSp.h"
#include "RaProcessor.h"

using namespace Decent::RaSgx;
using namespace Decent::Tools;

SelfRaReportGenerator::SelfRaReportGenerator(std::unique_ptr<Decent::Sgx::RaProcessorSp>& raSp, std::unique_ptr<RaProcessorClient>& raClient) :
	m_raSp(std::move(raSp)),
	m_raClient(std::move(raClient))
{
}

SelfRaReportGenerator::~SelfRaReportGenerator()
{
}

void SelfRaReportGenerator::GenerateSelfRaReport(std::string & platformType, std::string & selfRaReport)
{
	using namespace Decent::Ra;

	if (!m_raSp || !m_raClient)
	{
		throw Decent::RuntimeException("Decent::RaSgx::SelfRaReportGenerator::GenerateSelfRaReport - "
			"Invalid Argument was given.");
	}
	
	sgx_ra_msg0r_t msg0r;
	sgx_ra_msg1_t msg1;
	std::vector<uint8_t> msg2;
	std::vector<uint8_t> msg3;
	std::vector<uint8_t> msg4;

	sgx_report_data_t reportData;

	m_raSp->Init();
	m_raSp->GetMsg0r(msg0r);
	m_raClient->ProcessMsg0r(msg0r, msg1);
	m_raSp->ProcessMsg1(msg1, msg2);
	m_raClient->ProcessMsg2(*reinterpret_cast<sgx_ra_msg2_t*>(msg2.data()), msg2.size(), msg3);
	m_raSp->ProcessMsg3(*reinterpret_cast<sgx_ra_msg3_t*>(msg3.data()), msg3.size(), msg4, &reportData);

	PRINT_I("Received self IAS RA report:");
	PRINT_I("%s", m_raSp->GetIasReportStr().c_str());
	PRINT_I("");

	platformType = RaReport::sk_ValueReportTypeSgx;

	JsonDoc doc;
	JsonSetVal(doc, RaReport::sk_LabelIasReport, m_raSp->GetIasReportStr());
	JsonSetVal(doc, RaReport::sk_LabelIasSign, m_raSp->GetIasReportSign());
	JsonSetVal(doc, RaReport::sk_LabelIasCertChain, m_raSp->GetIasReportCert());
	JsonSetVal(doc, RaReport::sk_LabelOriRepData, SerializeStruct(reportData));

	JsonValue report = std::move(static_cast<JsonValue&>(doc));
	JsonSetVal(doc, RaReport::sk_LabelRoot, report);

	selfRaReport = Json2String(doc);
}
