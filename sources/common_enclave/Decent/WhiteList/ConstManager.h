#pragma once

#include <map>
#include <mutex>

namespace Decent
{
	namespace WhiteList
	{
		class ConstManager
		{
		public:
			static ConstManager& Get();

			ConstManager();
			virtual ~ConstManager();

			std::string GetWhiteList(const std::string& key) const;

			virtual bool AddWhiteList(const std::string& key, const std::string& listJson);

		private:
			std::map<std::string, std::string> m_listMap;
			mutable std::mutex m_listMapMutex;
		};
	}
}
