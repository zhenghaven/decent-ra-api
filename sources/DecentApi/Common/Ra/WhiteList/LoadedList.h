#pragma once

#include "StaticList.h"

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

			class LoadedList : public StaticList
			{
			public: //static member:
				static WhiteListType ParseWhiteListFromJson(const std::string & whiteListJson);

			public:
				LoadedList();

				LoadedList(const Decent::Ra::AppX509& certPtr);

				LoadedList(const std::string& whiteListJson);

				LoadedList(LoadedList* instPtr);

				LoadedList(const WhiteListType& whiteList);

				LoadedList(WhiteListType&& whiteList);

				LoadedList(const LoadedList& rhs);

				LoadedList(LoadedList&& rhs);

				virtual ~LoadedList() {}

				/**
				* \brief	Gets hash of the white list.
				*
				* \return	The white list hash.
				*/
				const std::string& GetWhiteListHash() const { return m_listHash; }

			private:
				std::string m_listHash;
			};
		}
	}
}
