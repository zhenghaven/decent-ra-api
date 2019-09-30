#pragma once

#include <limits>

#include "MbedTlsCppDefs.h"

namespace Decent
{
	namespace MbedTlsObj
	{
		/** \brief	A abstract class for RBG (Random Bits Generator). */
		class RbgBase
		{
		public: // static members:

			/**
			 * \brief	Call back function used for mbedTLS library.
			 *
			 * \param [in,out]	ctx	The pointer point to a RbgBase instance. Must not null.
			 * \param [out]	  	buf	The buffer to be filled with random bits.
			 * \param 		  	len	The length of the buffer.
			 *
			 * \return	mbedTLS errorcode.
			 */
			static int CallBack(void * ctx, unsigned char * buf, size_t len) noexcept;

		public:
			/** \brief	Default constructor */
			RbgBase() = default;

			/** \brief	Destructor */
			virtual ~RbgBase() {}

			/**
			 * \brief	Generate Random bits to fill the given buffer.
			 *
			 * \param [in,out]	buf 	If non-null, the buffer.
			 * \param 		  	size	The size.
			 */
			virtual void Rand(void* buf, const size_t size) = 0;

			/**
			 * \brief	Generate Random bits to fill a given C primitive type (e.g. struct).
			 *
			 * \tparam	T	Generic type parameter.
			 * \param [out]	stru	The struct.
			 */
			template<typename T>
			void RandStruct(T& stru)
			{
				Rand(&stru, sizeof(T));
			}

			/**
			 * \brief	Generate Random bits to fill a given container.
			 *
			 * \tparam	ContainerType	Type of the container.
			 * \param [out]	Container	The container.
			 */
			template<typename ContainerType>
			void RandContainer(ContainerType& Container)
			{
				using namespace Decent::MbedTlsObj::detail;

				Rand(GetPtr(Container), GetSize(Container));
			}
		};

		class Drbg : public RbgBase
		{
		public:
			Drbg();
			virtual ~Drbg();

			virtual void Rand(void* buf, const size_t size) override;

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
