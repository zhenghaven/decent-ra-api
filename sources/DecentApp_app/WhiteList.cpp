#include "../common/Ra/WhiteList/HardCoded.h"
#include "../common_app/Ra/WhiteList/Requester.h"

using namespace Decent::Ra::WhiteList;

HardCoded::HardCoded() :
	StaticTypeList(
		{
			std::make_pair<std::string, std::string>(HardCoded::sk_decentServerLabel, ""),
		}
		)
{
}

Requester::Requester() :
	m_key("TestHashList_01"),
	m_whiteList{
	std::make_pair<std::string, std::string>("TestAppName", "TestAppHash"),
}
{
}
