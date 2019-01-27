#pragma once

#include "WhiteList.h"

namespace Decent
{
	namespace Ra
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

				virtual bool CheckListsAreMatch(const WhiteListType& otherMap) const;

				virtual bool operator==(const StaticTypeList& other) const;
				virtual bool operator!=(const StaticTypeList& other) const;

			private:
				const WhiteListType m_listMap;
			};
		}
	}
}
