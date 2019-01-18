#pragma once

#include <string>

namespace Decent
{
	namespace Net
	{
		class SecureCommLayer
		{
		public:
			virtual ~SecureCommLayer() {}

			//virtual bool DecryptMsg(std::string& outMsg, const std::string& msg) = 0;

			//virtual bool EncryptMsg(std::string& outMsg, const std::string& inMsg) = 0;

			virtual bool ReceiveMsg(void* const connectionPtr, std::string& outMsg) = 0;
			virtual bool SendMsg(void* const connectionPtr, const std::string& inMsg) = 0;

			virtual operator bool() const = 0;
		};
	}
}
