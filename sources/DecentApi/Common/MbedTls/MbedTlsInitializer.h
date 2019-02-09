#pragma once

namespace Decent
{
	namespace MbedTlsHelper
	{
		class MbedTlsInitializer
		{
		public:
			static MbedTlsInitializer& GetInst();
			MbedTlsInitializer();
			~MbedTlsInitializer();
		};
	}
}
