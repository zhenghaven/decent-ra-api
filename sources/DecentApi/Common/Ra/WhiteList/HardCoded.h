#pragma once

#include "StaticTypeList.h"

namespace Decent
{
	namespace Ra
	{
		namespace WhiteList
		{
			constexpr char const sk_nameDecentServer[] = "DecentServer";

			class HardCoded : public StaticTypeList
			{
			public:

				HardCoded();

				~HardCoded() {}
			};
		}
	}
}
