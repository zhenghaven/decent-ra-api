#include "../../common/WhiteList/HardCoded.h"

using namespace Decent::WhiteList;

const WhiteListType& HardCoded::Get()
{
	static WhiteListType whiteList = 
	{
		std::make_pair<std::string, std::string>(HardCoded::sk_decentServerLabel, ""),
	};

	return whiteList;
}
