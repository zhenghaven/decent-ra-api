#pragma once

#include <memory>

#include "../SelfRaReportGenerator.h"

class SgxRaProcessorSp;
class SgxDecentRaProcessorClient;

class SgxSelfRaReportGenerator : public SelfRaReportGenerator
{
public:
	SgxSelfRaReportGenerator(std::unique_ptr<SgxRaProcessorSp>& raSp, std::unique_ptr<SgxDecentRaProcessorClient>& raClient);
	virtual ~SgxSelfRaReportGenerator();

	virtual bool GenerateSelfRaReport(std::string& platformType, std::string& selfRaReport) override;

private:
	std::unique_ptr<SgxRaProcessorSp> m_raSp;
	std::unique_ptr<SgxDecentRaProcessorClient> m_raClient;
};
