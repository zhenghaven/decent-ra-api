#pragma once

#include "StaticTypeList.h"

namespace Decent
{
	namespace WhiteList
	{
		class HardCoded : public StaticTypeList
		{
		public:
			static constexpr char const sk_decentServerLabel[] = "DecentServer";

			HardCoded();

			~HardCoded() {}
		};
	}
}
