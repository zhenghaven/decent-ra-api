#pragma once

#include "StaticTypeList.h"

namespace Decent
{
	namespace Ra
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
}
