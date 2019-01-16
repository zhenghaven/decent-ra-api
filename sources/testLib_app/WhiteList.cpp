#include "../common/WhiteList/HardCoded.h"

using namespace Decent::WhiteList;

HardCoded::HardCoded() :
	StaticTypeList(
		{
			std::make_pair<std::string, std::string>(HardCoded::sk_decentServerLabel, ""),
		}
		)
{
}
