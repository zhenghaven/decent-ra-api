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
			static void GenerateAndStoreServerX509Cert(SelfRaReportGenerator& reportGenerator, ServerStates& decentStates);

		public:
			virtual ~SelfRaReportGenerator() {}

			virtual void GenerateSelfRaReport(std::string& platformType, std::string& selfRaReport) = 0;
		};
	}
}

