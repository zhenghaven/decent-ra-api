#pragma once

namespace Decent
{
	namespace MbedTlsObj
	{
		class MbedTlsInitializer
		{
		public:
			static MbedTlsInitializer& GetInst();
			~MbedTlsInitializer();

		private:
			MbedTlsInitializer();

		};
	}
}
