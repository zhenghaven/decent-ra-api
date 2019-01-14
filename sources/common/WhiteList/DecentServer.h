#pragma once

#include <map>
#include <mutex>

#include "../CommonType.h"

namespace Decent
{
	namespace WhiteList
	{
		class DecentServer
		{
		public:
			static DecentServer& Get();

		public:
			~DecentServer();

		private:
			DecentServer();

			std::map<std::string, TimeStamp> m_acceptedNodes;
			std::mutex m_acceptedNodesMutex;
		};
	}
}