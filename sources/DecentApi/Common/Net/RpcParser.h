#pragma once

#include <cstring>

#include <string>

#include "RpcDefs.h"

namespace Decent
{
	namespace Net
	{
		class RpcParser
		{
		public:
			RpcParser() = delete;

			/**
			 * \brief	Constructor
			 *
			 * \exception	RuntimeException	Thrown when metadata doesn't match (probably caused by the inconsistency of RPC version).
			 *
			 * \param [in,out]	binary	The binary.
			 */
			RpcParser(std::vector<uint8_t>&& binary) :
				m_binary(std::forward<std::vector<uint8_t> >(binary)),
				m_currPos(m_binary.begin()),
				m_argCount(InternalGetPrimArg<uint32_t>())
			{}

			/** \brief	Destructor */
			virtual ~RpcParser()
			{}

			/**
			 * \brief	Gets primitive argument
			 *
			 * \exception	RuntimeException	Thrown when metadata doesn't match (probably caused by the inconsistency of RPC version).
			 *
			 * \tparam	ArgType	Type of the argument type.
			 *
			 * \return	The primitive argument.
			 */
			template<typename ArgType>
			ArgType& GetPrimitiveArg()
			{
				auto argType = InternalGetPrimArg<uint8_t>();
				auto argSize = InternalGetPrimArg<uint64_t>();

				if (argType != sk_rpcBlockTypePrimitive)
				{
					throw RuntimeException("Failed to parse RPC binary block, because the requested type doesn't match the type stored in binary block.");
				}

				if (argSize != sizeof(ArgType))
				{
					throw RuntimeException("Failed to parse RPC binary block, because the size of the primitive type doesn't match.");
				}

				return InternalGetPrimArg<ArgType>();
			}

			/**
			 * \brief	Gets c string argument
			 *
			 * \exception	RuntimeException	Thrown when metadata doesn't match (probably caused by the inconsistency of RPC version).
			 *
			 * \return	Null if it fails, else the c string argument.
			 */
			const char* GetCStringArg()
			{
				auto argType = InternalGetPrimArg<uint8_t>();
				auto argSize = InternalGetPrimArg<uint64_t>();

				if (argType != sk_rpcBlockTypeNullTerminated)
				{
					throw RuntimeException("Failed to parse RPC binary block, because the requested type doesn't match the type stored in binary block.");
				}

				auto it = InternalGetNext(argSize);

				return reinterpret_cast<const char*>(&(*it));
			}

			/**
			 * \brief	Gets string argument
			 *
			 * \exception	RuntimeException	Thrown when metadata doesn't match (probably caused by the inconsistency of RPC version).
			 *
			 * \return	The string argument.
			 */
			std::string GetStringArg()
			{
				return GetCStringArg();
			}

			/**
			 * \brief	Gets binary argument
			 *
			 * \exception	RuntimeException	Thrown when metadata doesn't match (probably caused by the inconsistency of RPC version).
			 *
			 * \return	The binary argument.
			 */
			std::pair<std::vector<uint8_t>::const_iterator, std::vector<uint8_t>::const_iterator> GetBinaryArg()
			{
				auto argType = InternalGetPrimArg<uint8_t>();
				auto argSize = InternalGetPrimArg<uint64_t>();

				if (argType != sk_rpcBlockTypeVariableLength)
				{
					throw RuntimeException("Failed to parse RPC binary block, because the requested type doesn't match the type stored in binary block.");
				}

				auto itBegin = InternalGetNext(argSize);

				return std::make_pair(itBegin, itBegin + argSize);
			}

		protected:

			std::vector<uint8_t>::iterator InternalGetNext(size_t size)
			{
				if (std::distance(m_currPos, m_binary.end()) < static_cast<int64_t>(size))
				{
					throw RuntimeException("Failed to parse RPC binary block, because the binary size is less than needed.");
				}

				std::vector<uint8_t>::iterator tmpIt = m_currPos;
				m_currPos += size;
				return tmpIt;
			}

			template<typename ArgType>
			ArgType& InternalGetPrimArg()
			{
				auto& byteRef = *InternalGetNext(sizeof(ArgType));
				auto bytePtr = &byteRef;
				return *reinterpret_cast<ArgType*>(bytePtr);
			}

		private:
			std::vector<uint8_t> m_binary;

			std::vector<uint8_t>::iterator m_currPos;

			uint32_t m_argCount;
		};
	}
}
