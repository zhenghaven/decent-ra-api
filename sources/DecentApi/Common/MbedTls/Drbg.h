#pragma once

#include <limits>

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

		template<typename ResultType>
		class DrbgRandGenerator
		{
		public:
			typedef ResultType result_type;

			static constexpr ResultType max()
			{
				return std::numeric_limits<ResultType>::max();
			}

			static constexpr ResultType min()
			{
				return std::numeric_limits<ResultType>::min();
			}

		public:
			DrbgRandGenerator() = default;

			virtual ~DrbgRandGenerator()
			{}

			ResultType operator()()
			{
				ResultType res;
				m_drbg.Rand(&res, sizeof(res));
				return res;
			}

		private:
			MbedTlsObj::Drbg m_drbg;
		};
	}
}
