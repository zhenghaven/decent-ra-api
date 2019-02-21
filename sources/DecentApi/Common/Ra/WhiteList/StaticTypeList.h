#pragma once

#include "WhiteList.h"

#include "../../Tools/JsonForwardDeclare.h"

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

				StaticTypeList(WhiteListType&& whiteList) :
					m_listMap(std::forward<WhiteListType>(whiteList))
				{}

				StaticTypeList(const StaticTypeList& rhs) :
					m_listMap(rhs.m_listMap)
				{}

				StaticTypeList(StaticTypeList&& rhs) :
					m_listMap(std::forward<WhiteListType>(rhs.m_listMap))
				{}

				~StaticTypeList();

				/**
				 * \brief	Gets the white list (map) as const reference.
				 *
				 * \return	The white list (map).
				 */
				const WhiteListType& GetMap() const;

				/**
				 * \brief	Check if the given hash is in the white list, and return the app name in the list.
				 *
				 * \param 		  	hashStr   	The hash in Base-64 string.
				 * \param [in,out]	outAppName	Name of the application.
				 *
				 * \return	True if the hash is in the white list, false if it's not.
				 */
				virtual bool CheckHash(const std::string& hashStr, std::string& outAppName) const;

				/**
				 * \brief	Check if the given hash is in the white list and the app name are match.
				 *
				 * \param	hashStr	The hash in Base-64 string.
				 * \param	appName	Name of the application.
				 *
				 * \return	True if the hash is in the white list and app name is the same, false if it's not.
				 */
				virtual bool CheckHashAndName(const std::string& hashStr, const std::string& appName) const;

				/**
				 * \brief	Check if the list in this instance and the given list are match.
				 * 			Match means both hash and app name are equal.
				 *
				 * \param	otherMap	The other map (list).
				 *
				 * \return	True if it succeeds, false if it fails.
				 */
				virtual bool CheckListsAreMatch(const WhiteListType& otherMap) const;

				/**
				 * \brief	Check if the given list is within the range of the list in this instance.
				 * 			Items in the otherMap must also be in this instance. 
				 * 			Items in this instance may not be in the otherMap.
				 * 			For each item, both hash and app name are compared.
				 *
				 * \param	otherMap	The other map (list).
				 *
				 * \return	True if it succeeds, false if it fails.
				 */
				virtual bool CheckListsWithinRange(const WhiteListType& otherMap) const;

				/**
				 * \brief	Equality operator
				 * 			Check if the list in the right hand side is exact same as the left side.
				 * 			Basically, it is calling CheckListsAreMatch.
				 *
				 * \param	other	The right hand side.
				 *
				 * \return	True if the parameters are considered equivalent.
				 */
				virtual bool operator==(const StaticTypeList& other) const;

				/**
				 * \brief	Inequality operator
				 * 			Basically, it is calling !operator==.
				 *
				 * \param	other	The right hand side.
				 *
				 * \return	True if the parameters are not considered equivalent.
				 */
				virtual bool operator!=(const StaticTypeList& other) const;

				/**
				 * \brief	Greater-than-or-equal comparison operator
				 * 			Basically, it is calling CheckListsWithinRange.
				 *
				 * \param	other	The other.
				 *
				 * \return	True if the first parameter is greater than or equal to the second.
				 */
				virtual bool operator>=(const StaticTypeList& other) const;

				/**
				 * \brief	Converts this white list to a JSON format.
				 *
				 * \param [in,out]	jsonDoc	The JSON document.
				 *
				 * \return	JsonDoc as a Tools::JsonValue&amp;
				 */
				virtual Tools::JsonValue& ToJson(Tools::JsonDoc& jsonDoc) const;

			private:
				WhiteListType m_listMap;
			};
		}
	}
}
