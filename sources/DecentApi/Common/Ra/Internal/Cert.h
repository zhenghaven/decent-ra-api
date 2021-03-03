#pragma once

#include <cstdint>
#include <ctime>

#include <string>

namespace Decent
{
	namespace Ra
	{
		namespace detail
		{
			constexpr char const gsk_x509PlatformTypeOid[] = "2.25.294010332531314719175946865483017979201";
			constexpr char const gsk_x509SelfRaReportOid[] = "2.25.210204819921761154072721866869208165061";
			constexpr char const gsk_x509LaIdOid[] = "2.25.128165920542469106824459777090692906263";
			constexpr char const gsk_x509WhiteListOid[] = "2.25.219117063696833207876173044031738000021";

			constexpr int64_t gsk_x509ValidTime = 31536000; // 365 days in seconds.

			inline std::string X509FormatTime(const std::tm& time)
			{
				std::string res(sizeof("YYYYMMDDHHMMSS"), '\0');

				strftime(&res[0], res.size(), "%Y%m%d%H%M%S", &time);

				for (; res.size() > 0 && res.back() == 0; res.pop_back()) {}

				return res;
			}
		}
	}
}