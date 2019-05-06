#pragma once

#include <string>

namespace Decent
{
	namespace Net
	{
		class ConnectionBase;
	}

	namespace Ra
	{
		class DecentServer
		{
		public:
			virtual std::string GetDecentSelfRAReport() const = 0;
			virtual void LoadConstWhiteList(const std::string& key, const std::string& whiteList) = 0;
			virtual void ProcessAppCertReq(const std::string& wListKey, Net::ConnectionBase& connection) = 0;

		protected:
			virtual std::string GenerateDecentSelfRAReport() = 0;
		};
	}
}
