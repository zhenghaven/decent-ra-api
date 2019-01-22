#pragma once

#include <memory>

#include "../CommonEnclave/Ra/SelfRaReportGenerator.h"

namespace Decent
{
	namespace Sgx
	{
		class RaProcessorSp;
	}

	namespace RaSgx
	{
		class RaProcessorClient;

		class SelfRaReportGenerator : public Decent::Ra::SelfRaReportGenerator
		{
		public:
			SelfRaReportGenerator(std::unique_ptr<Sgx::RaProcessorSp>& raSp, std::unique_ptr<RaSgx::RaProcessorClient>& raClient);
			virtual ~SelfRaReportGenerator();

			virtual bool GenerateSelfRaReport(std::string& platformType, std::string& selfRaReport) override;

		private:
			std::unique_ptr<Sgx::RaProcessorSp> m_raSp;
			std::unique_ptr<RaSgx::RaProcessorClient> m_raClient;
		};
	}
}
