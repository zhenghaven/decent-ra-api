#pragma once

#include <cstdint>

#include <vector>

#include "../../Common/ArrayPtrAndSize.h"

namespace Decent
{
	namespace Tools
	{
		/**
		 * \brief	Untrusted Buffer. This object holds a buffer that allocated in untrusted side (i.e.
		 * 			application side, non-enclave side).
		 */
		class UntrustedBuffer
		{
		public:
			UntrustedBuffer() = delete;

			/**
			 * \brief	Constructor
			 *
			 * \param [in,out]	ptr 	If non-null, the pointer to the untrusted buffer.
			 * \param 		  	size	The size of that buffer.
			 */
			UntrustedBuffer(uint8_t* ptr, const size_t size) :
				m_ptr(ptr),
				m_size(size)
			{}

			/** \brief	Destructor. This will call the function in untrusted side to free the buffer. */
			virtual ~UntrustedBuffer();

			/**
			 * \brief	Reads the data into buffer allocated in trusted side.
			 *
			 * \param [in,out]	tBufPtr 	If non-null, the buffer pointer pointing to the trusted buffer.
			 * \param 		  	tBufSize	Size of the trusted buffer.
			 */
			virtual void Read(void* tBufPtr, size_t tBufSize) const
			{
				uint8_t* bufBytePtr = static_cast<uint8_t*>(tBufPtr);
				const size_t size2Cp = tBufSize >= m_size ? m_size : tBufSize;

				std::copy(m_ptr, m_ptr + size2Cp, bufBytePtr);
			}

			/**
			 * \brief	Reads the data into buffer allocated in trusted side.
			 *
			 * \tparam	Container	Type of the container.
			 * \param [in,out]	tBuf	The buffer allocated in trusted side.
			 */
			template<typename Container>
			void Read(Container& tBuf) const
			{
				Read(ArrayPtrAndSize::GetPtr(tBuf), ArrayPtrAndSize::GetSize(tBuf));
			}

			/**
			 * \brief	Reads the data into buffer allocated in trusted side.
			 *
			 * \return	A std::vector&lt;uint8_t&gt; that holds the data stored in trusted side.
			 */
			std::vector<uint8_t> Read() const
			{
				return std::vector<uint8_t>(m_ptr, m_ptr + m_size);
			}

		private:
			uint8_t * m_ptr;
			size_t m_size;
		};
	}
}