#pragma once

#include "StaticList.h"

#include "../AppX509Cert.h"

namespace Decent
{
	namespace Ra
	{
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

				template<typename _AppCertTrait>
				LoadedList(const Ra::AppX509CertBase<_AppCertTrait>& certPtr) :
					LoadedList(certPtr.GetWhiteList())
				{}

				LoadedList(const std::string& whiteListJson) :
					LoadedList(ParseWhiteListFromJson(whiteListJson))
				{}

				LoadedList(LoadedList* instPtr) :
					LoadedList(instPtr ? std::move(*instPtr) : LoadedList())
				{}

				LoadedList(const WhiteListType& whiteList);

				LoadedList(WhiteListType&& whiteList);

				LoadedList(const LoadedList& rhs) :
					StaticList(rhs),
					m_listHash(rhs.m_listHash)
				{}

				LoadedList(LoadedList&& rhs) :
					StaticList(std::forward<StaticList>(rhs)),
					m_listHash(std::move(rhs.m_listHash))
				{}

				virtual ~LoadedList()
				{}

				/**
				* \brief	Gets hash of the white list.
				*
				* \return	The white list hash.
				*/
				const std::string& GetWhiteListHash() const
				{
					return m_listHash;
				}

			private:
				std::string m_listHash;
			};
		}
	}
}
