#pragma once

#include <string>
#include <memory>

namespace Decent
{
	namespace Ra
	{
		class DecentApp
		{
		public:
			virtual std::string GetAppX509Cert() = 0;
		};
	}
}
