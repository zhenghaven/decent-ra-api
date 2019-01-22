#pragma once

#include <string>

namespace Decent
{
	namespace Ra
	{
		class ServerX509;

		class SelfRaReportGenerator
		{
		public:
			static bool GenerateAndStoreServerX509Cert(SelfRaReportGenerator& reportGenerator);

		public:
			virtual ~SelfRaReportGenerator() {}

			virtual bool GenerateSelfRaReport(std::string& platformType, std::string& selfRaReport) = 0;
		};
	}
}

