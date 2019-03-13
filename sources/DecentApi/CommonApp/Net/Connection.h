#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace Json
{
	class Value;
}

namespace Decent
{
	namespace Net
	{
		class SmartMessages;

		class Connection
		{
		public:
			virtual ~Connection() noexcept {}

			virtual size_t SendRaw(const void* const dataPtr, const size_t size) = 0;
			virtual void SendRawGuarantee(const void* const dataPtr, const size_t size);

			virtual void SendPack(const void* const dataPtr, const size_t size);
			virtual void SendPack(const std::string& msg);
			virtual void SendPack(const std::vector<uint8_t>& msg);
			virtual void SendPack(const SmartMessages& msg);
			virtual void SendPack(const Json::Value& msg);

			virtual size_t ReceiveRaw(void* const bufPtr, const size_t size) = 0;
			virtual void ReceiveRawGuarantee(void* const bufPtr, const size_t size);

			virtual void ReceivePack(std::string& msg);
			virtual void ReceivePack(std::vector<uint8_t>& msg);

			virtual size_t ReceivePack(char*& dest);
			virtual void ReceivePack(Json::Value& msg);

			virtual void Terminate() noexcept = 0;
		};
	}
}
