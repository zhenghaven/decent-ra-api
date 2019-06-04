#pragma once

#include <cstring>

#include <string>

#include "RpcDefs.h"

namespace Decent
{
	namespace Net
	{
		template<typename DataType>
		class RpcArgRefCountinousBinPrimitive
		{
		public:
			RpcArgRefCountinousBinPrimitive(std::vector<uint8_t>& binRef, size_t startPos) :
				m_binRef(binRef),
				m_startPos(startPos)
			{}

			virtual ~RpcArgRefCountinousBinPrimitive()
			{}

			DataType& Get()
			{
				auto& byteRef = m_binRef[m_startPos];
				return reinterpret_cast<DataType&>(byteRef);
			}

			const DataType& Get() const
			{
				const auto& byteRef = m_binRef[m_startPos];
				return reinterpret_cast<const DataType&>(byteRef);
			}

			operator DataType&()
			{
				return Get();
			}

			operator const DataType&() const
			{
				return Get();
			}

			RpcArgRefCountinousBinPrimitive& operator=(const DataType& rhs)
			{
				Get() = rhs;
				return *this;
			}

			RpcArgRefCountinousBinPrimitive& operator=(DataType&& rhs)
			{
				Get() = std::forward<DataType>(rhs);
				return *this;
			}

		private:
			std::vector<uint8_t>& m_binRef;
			const size_t m_startPos;
		};

		class RpcArgRefCountinousBinVariable
		{
		public:
			RpcArgRefCountinousBinVariable(std::vector<uint8_t>& binRef, size_t startPos, size_t len) :
				m_binRef(binRef),
				m_startPos(startPos),
				m_len(len)
			{}

			virtual ~RpcArgRefCountinousBinVariable()
			{}

			std::vector<uint8_t>::iterator begin()
			{
				return m_binRef.begin() + m_startPos;
			}

			std::vector<uint8_t>::const_iterator begin() const
			{
				return m_binRef.cbegin() + m_startPos;
			}

			std::vector<uint8_t>::const_iterator cbegin() const
			{
				return begin();
			}

			std::vector<uint8_t>::iterator end()
			{
				return m_binRef.begin() + m_startPos + m_len;
			}

			std::vector<uint8_t>::const_iterator end() const
			{
				return m_binRef.cbegin() + m_startPos + m_len;
			}

			std::vector<uint8_t>::const_iterator cend() const
			{
				return end();
			}

			size_t GetSize() const
			{
				return m_len;
			}

		private:
			std::vector<uint8_t>& m_binRef;
			const size_t m_startPos;
			const size_t m_len;
		};

		class RpcArgRefCountinousBinString : public RpcArgRefCountinousBinVariable
		{
		public:
			using RpcArgRefCountinousBinVariable::RpcArgRefCountinousBinVariable;

			~RpcArgRefCountinousBinString()
			{}

			const char* Get() const
			{
				const auto& byteRef = *begin();
				return reinterpret_cast<const char*>(&byteRef);
			}

			operator const char*() const
			{
				return Get();
			}

			void Fill(const char* str)
			{
				static_assert(sizeof(uint8_t) == sizeof(char), "The size of 'char' is other than 1 byte; this is not implemented for this case.");

				size_t strLen = std::strlen(str);

				if (strLen + 1 > GetSize()) //GetSize() return the size of the entire block, including the null character.
				{
					throw RuntimeException("The length of the string given to the RPC string fill function is larger than what declared.");
				}

				std::copy(str, str + strLen + 1, Get());
			}

			void Fill(const std::string& str)
			{
				return Fill(str.c_str());
			}

		private:
			char* Get()
			{
				auto& byteRef = *begin();
				return reinterpret_cast<char*>(&byteRef);
			}
		};

		class RpcWriter
		{
		public://static member:

			template<typename ArgType>
			static inline constexpr size_t CalcSizePrim()
			{
				return sizeof(ArgType);
			}

			static inline size_t CalcSizeStr(const char* str)
			{
				return std::strlen(str) + 1;
			}

			static inline size_t CalcSizeStr(const std::string& str)
			{
				return CalcSizeStr(str.c_str());
			}

			static inline size_t CalcSizeStr(size_t size)
			{
				return size + 1;
			}

			static inline size_t CalcSizeBin(size_t size)
			{
				return size;
			}

		private://static member:
			static inline constexpr size_t CalcInitSize(bool writeSize, size_t size, uint32_t argCount)
			{
				return (writeSize ? sizeof(*m_totalLen) : 0) +         //total size (if needed)
					sizeof(m_argCount) +                               //argument count
					size +                                             //total size of all arguments
					(argCount * (sizeof(uint8_t) + sizeof(uint64_t))); //metadata per argument
			}

			static inline constexpr uint64_t* InitTotalLenPtr(bool writeSize, std::vector<uint8_t>& bin)
			{
				return writeSize ?
					reinterpret_cast<decltype(m_totalLen)>(&bin[0]) :
					nullptr;
			}

			static inline uint32_t& InitArgCountRef(bool writeSize, std::vector<uint8_t>& bin)
			{
				return writeSize ?
					reinterpret_cast<decltype(m_argCount)>(bin[sizeof(*m_totalLen)]) :
					reinterpret_cast<decltype(m_argCount)>(bin[0]);
			}

			static inline size_t InitCurrentPos(bool writeSize)
			{
				return (writeSize ? sizeof(*m_totalLen) : 0) + //total size (if needed)
					sizeof(m_argCount);                        //argument count
			}

		public:
			RpcWriter() = delete;

			/**
			 * \brief	Constructor
			 *
			 * \param	size	   	Size of the entire binary block to be allocated. It is used to reduce the
			 * 						need for memory reallocation when adding more arguments to this object.
			 * 						The actual reserved size will be this added with the size of the
			 * 						'totalLen' variable (if it is required by turning on the next argument),
			 * 						and the space needed for the metadata per argument.
			 * \param	argCount   	Number of arguments.
			 * \param	sizeAtFront	(Optional) True to write size at the beginning. The size of the entire
			 * 						binary block is written to the beginning of this block, so that the
			 * 						entire binary block can be sent at one function call.
			 */
			explicit RpcWriter(size_t size, uint32_t argCount, bool sizeAtFront = true) :
				m_sizeAtFront(sizeAtFront),
				m_binary(CalcInitSize(m_sizeAtFront, size, argCount)),
				m_totalLen(InitTotalLenPtr(m_sizeAtFront, m_binary)),
				m_argCount(InitArgCountRef(m_sizeAtFront, m_binary)),
				m_currPos(InitCurrentPos(m_sizeAtFront))
			{
				UpdateTotalLength();
			}

			/** \brief	Destructor */
			virtual ~RpcWriter()
			{}

			/**
			 * \brief	Adds primitive argument
			 *
			 * \exception	RuntimeException	Thrown when the allocated space is not big enough.
			 *
			 * \tparam	ArgType	Type of the argument type.
			 *
			 * \return	A RpcArgRefCountinousBinPrimitive&lt;ArgType&gt;
			 */
			template<typename ArgType>
			RpcArgRefCountinousBinPrimitive<ArgType> AddPrimitiveArg()
			{
				auto argType = InternalAddPrimArg<uint8_t>();
				auto argSize = InternalAddPrimArg<uint64_t>();

				argType.Get() = sk_rpcBlockTypePrimitive;
				argSize.Get() = sizeof(ArgType);

				//Update the counters:
				m_argCount++;

				return InternalAddPrimArg<ArgType>();
			}

			/**
			 * \brief	Adds a string argument
			 *
			 * \exception	RuntimeException	Thrown when the allocated space is not big enough.
			 *
			 * \param	strLen	The length of the string, which doesn't count the null-terminator.
			 *
			 * \return	A RpcArgRefCountinousBinString.
			 */
			RpcArgRefCountinousBinString AddStringArg(size_t strLen)
			{
				auto argType = InternalAddPrimArg<uint8_t>();
				auto argSize = InternalAddPrimArg<uint64_t>();

				argType.Get() = sk_rpcBlockTypeNullTerminated;
				argSize.Get() = strLen + 1;

				//Update the counters:
				m_argCount++;

				return RpcArgRefCountinousBinString(m_binary, InternalAllocate(strLen + 1), strLen + 1);
			}

			/**
			 * \brief	Adds a binary argument
			 *
			 * \exception	RuntimeException	Thrown when the allocated space is not big enough.
			 *
			 * \return	A RpcArgRefCountinousBinVariable.
			 */
			RpcArgRefCountinousBinVariable AddBinaryArg(size_t size)
			{
				auto argType = InternalAddPrimArg<uint8_t>();
				auto argSize = InternalAddPrimArg<uint64_t>();

				argType.Get() = sk_rpcBlockTypeVariableLength;
				argSize.Get() = size;

				//Update the counters:
				m_argCount++;

				return RpcArgRefCountinousBinVariable(m_binary, InternalAllocate(size), size);
			}

			/**
			 * \brief	Gets binary array
			 *
			 * \return	The binary array.
			 */
			const std::vector<uint8_t>& GetBinaryArray() const
			{
				return m_binary;
			}

			/**
			 * \brief	Query if this instance has total size written at front
			 *
			 * \return	True if size at front, false if not.
			 */
			bool HasSizeAtFront() const
			{
				return m_sizeAtFront;
			}

		protected:

			/** \brief	Updates the total length */
			void UpdateTotalLength()
			{
				if (m_totalLen)
				{
					*m_totalLen = m_binary.size() - sizeof(*m_totalLen);
				}
			}

			size_t InternalAllocate(size_t size)
			{
				if (m_currPos + size > m_binary.size())
				{
					throw RuntimeException("The RPC writer doesn't have enough space to add a new argument.");
				}

				size_t tmpPos = m_currPos;
				m_currPos += size;
				return tmpPos;
			}

			template<typename ArgType>
			RpcArgRefCountinousBinPrimitive<ArgType> InternalAddPrimArg()
			{
				return RpcArgRefCountinousBinPrimitive<ArgType>(m_binary, InternalAllocate(sizeof(ArgType)));
			}

		private:
			const bool m_sizeAtFront;

			std::vector<uint8_t> m_binary;

			uint64_t* m_totalLen;
			uint32_t& m_argCount;

			size_t m_currPos;
		};
	}
}
