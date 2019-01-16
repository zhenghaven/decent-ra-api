#pragma once

#include "WhiteList.h"

namespace Decent
{
	namespace WhiteList
	{
		class StaticTypeList
		{
		public:
			StaticTypeList() = delete;
			StaticTypeList(const WhiteListType& whiteList);
			~StaticTypeList();

			const WhiteListType& GetMap() const;

			virtual bool CheckWhiteList(const std::string& hashStr, std::string& outAppName) const;

			virtual bool CheckWhiteListWithHint(const std::string& hashStr, const std::string& hintAppName) const;

			virtual bool CheckListsAreMatch(const WhiteListType& otherMap) const;

			virtual bool GetHash(const std::string& appName, std::string& outHash) const;

			virtual bool operator==(const StaticTypeList& other) const;
			virtual bool operator!=(const StaticTypeList& other) const;

		private:
			const WhiteListType m_listMap;
		};
	}
}
