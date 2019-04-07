#pragma once

#include <map>
#include <string>

namespace Decent
{
	namespace Ra
	{
		namespace WhiteList
		{
			/**
			 * \typedef	std::map<std::string, std::string> WhiteListType
			 *
			 * \brief	Defines an alias representing type of the white list 
			 * 			in the format of Map[Hash] = App_Name.
			 */
			typedef std::map<std::string, std::string> WhiteListType;

			/**
			 * \brief	The string that defines the name of the Decent Server in the white list.
			 */
			constexpr char const sk_nameDecentServer[] = "DecentServer";
		}
	}
}
