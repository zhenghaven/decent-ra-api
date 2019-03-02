#pragma once

#include <string>

namespace Decent
{
	namespace Ra
	{
		class ServerStates;

		class SelfRaReportGenerator
		{
		public:
			static bool GenerateAndStoreServerX509Cert(SelfRaReportGenerator& reportGenerator, ServerStates& decentStates);

		public:
			virtual ~SelfRaReportGenerator() {}

			virtual bool GenerateSelfRaReport(std::string& platformType, std::string& selfRaReport) = 0;
		};
	}
}

