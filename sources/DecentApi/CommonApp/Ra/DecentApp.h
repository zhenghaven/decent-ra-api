#pragma once

#include <string>
#include <memory>

namespace Decent
{
	namespace Net
	{
		class Connection;
	}

	namespace Ra
	{
		class DecentApp
		{
		public:
			virtual bool GetX509FromServer(const std::string& decentId, Net::Connection& connection) = 0;

			virtual const std::string& GetAppCert() const = 0;
		};
	}
}
