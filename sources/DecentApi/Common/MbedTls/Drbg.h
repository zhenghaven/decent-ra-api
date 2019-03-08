#pragma once

namespace Decent
{
	namespace MbedTlsObj
	{
		class Drbg
		{
		public:
			Drbg();
			virtual ~Drbg();

			virtual void Rand(void* buf, const size_t size);

			template<typename T>
			void RandStruct(T& stru)
			{
				Rand(&stru, sizeof(T));
			}

			template<typename T>
			void RandContainer(T& stru)
			{
				Rand(&(stru[0]), stru.size());
			}

			static int CallBack(void * ctx, unsigned char * buf, size_t len);

		private:
			void* m_state;
		};
	}
}
