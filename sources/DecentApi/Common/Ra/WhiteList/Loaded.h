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

				Loaded() :
					StaticTypeList(WhiteListType())
				{}

				Loaded(const Decent::Ra::AppX509& certPtr);

				Loaded(const std::string& whiteListJson);

				Loaded(Loaded* instPtr) :
					Loaded(instPtr ? std::move(*instPtr) : Loaded())
				{}

				Loaded(const WhiteListType& whiteList) :
					StaticTypeList(whiteList)
				{}

				Loaded(WhiteListType&& whiteList) :
					StaticTypeList(std::forward<WhiteListType>(whiteList))
				{}

				Loaded(const Loaded& rhs) :
					StaticTypeList(rhs)
				{}

				Loaded(Loaded&& rhs) :
					StaticTypeList(std::forward<StaticTypeList>(rhs))
				{}

				~Loaded() {}
			};
		}
	}
}
