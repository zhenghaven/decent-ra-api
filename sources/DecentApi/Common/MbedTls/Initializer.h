#pragma once

namespace Decent
{
	namespace MbedTlsObj
	{
		class Initializer
		{
		public: //static member:

			/**
			 * \brief	Initializes the mbedTLS library. An static Initializer will be constructed.
			 *
			 * \return	A reference to the Initializer.
			 */
			static Initializer& Init();

		public:

			virtual ~Initializer();

		protected:

			Initializer();
		};
	}
}
