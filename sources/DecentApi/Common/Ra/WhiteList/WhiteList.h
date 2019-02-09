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
		}
	}
}
