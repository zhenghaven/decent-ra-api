#pragma once

#include "StaticTypeList.h"

namespace Decent
{
	namespace Ra
	{
		class AppX509;

		namespace WhiteList
		{
			namespace LoadedJson
			{
				constexpr char const sk_LabelId[] = "ID";
				constexpr char const sk_LabelList[] = "List";
			}

			class Loaded : public StaticTypeList
			{
			public:
				static WhiteListType ParseWhiteListFromJson(const std::string & whiteListJson);

				Loaded() = delete;
				Loaded(Decent::Ra::AppX509* certPtr);
				Loaded(const std::string& whiteListJson);
				Loaded(const WhiteListType& whiteList);

				~Loaded() {}
			};
		}
	}
}
