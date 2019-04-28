#pragma once

#include <string>
#include <vector>
#include <cstdint>

#include "../../Common/Net/ConnectionBase.h"

namespace Decent
{
	namespace Net
	{
		class SmartMessages;

		class Connection : public ConnectionBase
		{
		public:
			virtual ~Connection() noexcept {}

			virtual void SendSmartMsg(const SmartMessages& msg);

			using ConnectionBase::SendPack;

			virtual void Terminate() noexcept = 0;
		};
	}
}
