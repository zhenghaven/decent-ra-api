#pragma once

#include <cstdint>

#include <string>
#include <vector>

#include "../ArrayPtrAndSize.h"
#include "RpcWriter.h"

namespace Decent
{
	namespace Net
	{
		class ConnectionBase;

		class SecureCommLayer
		{
		public:
			/** \brief	Default constructor */
			SecureCommLayer() = default;

			/** \brief	Destructor */
			virtual ~SecureCommLayer() {}

			/**
			 * \brief	Sets connection pointer
			 *
			 * \param [in,out]	connectionPtr	The connection pointer. Must not null!
			 */
			virtual void SetConnectionPtr(ConnectionBase& connectionPtr) = 0;

			//#################################################
			//#      Senders
			//#################################################

			/**
			 * \brief	Sends a secure message with specific length.
			 *
			 * \exception	Decent::Net::Exception	It's thrown when the operation is failed.
			 *
			 * \param	buf 	The pointer to data buffer (must not null).
			 * \param	size	Size of the data.
			 *
			 * \return	A size_t. Size of data that has been sent.
			 */
			virtual size_t SendRaw(const void* buf, const size_t size) = 0;

			/**
			 * \brief	Sends a secure message with specific length.
			 *
			 * \exception	Decent::Net::Exception	It's thrown when the operation is failed.
			 *
			 * \param [in,out]	connectionPtr	The connection pointer (must not null).
			 * \param 		  	buf			 	The pointer to data buffer (must not null).
			 * \param 		  	size		 	Size of the data.
			 *
			 * \return	A size_t. Size of data that has been sent.
			 */
			virtual size_t SendRaw(ConnectionBase& connectionPtr, const void* buf, const size_t size)
			{
				SetConnectionPtr(connectionPtr);
				return SendRaw(buf, size);
			}

			/**
			 * \brief	Sends a raw message. This function will keep calling SendRaw until entire message has
			 * 			been sent out. Exceptions from SendRaw will be thrown directly, thus, it can be
			 * 			stopped by exceptions.
			 *
			 * \exception	Decent::Net::Exception	It's thrown when the operation is failed.
			 *
			 * \param	buf 	The buffer. (must not null).
			 * \param	size	The size.
			 */
			virtual void SendRawAll(const void* buf, const size_t size)
			{
				size_t byteSent = 0;
				while (byteSent < size)
				{
					byteSent += SendRaw(static_cast<const uint8_t*>(buf) + byteSent, size - byteSent);
				}
			}

			/**
			 * \brief	Sends a raw message. This function will keep calling SendRaw until entire message has
			 * 			been sent out. Exceptions from SendRaw will be thrown directly, thus, it can be
			 * 			stopped by exceptions.
			 *
			 * \exception	Decent::Net::Exception	It's thrown when the operation is failed.
			 *
			 * \param [in,out]	connectionPtr	The connection pointer. (must not null).
			 * \param 		  	buf			 	The buffer. (must not null).
			 * \param 		  	size		 	The size.
			 */
			virtual void SendRawAll(ConnectionBase& connectionPtr, const void* buf, const size_t size)
			{
				SetConnectionPtr(connectionPtr);
				return SendRawAll(buf, size);
			}

			/**
			 * \brief	Sends a structure as message.
			 *
			 * \exception	Decent::Net::Exception	It's thrown when the operation is failed.
			 *
			 * \tparam	T	Generic type parameter.
			 * \param	buf	The structure to be sent.
			 */
			template<typename T>
			void SendStruct(const T& buf)
			{
				SendRawAll(&buf, sizeof(T));
			}

			/**
			 * \brief	Sends a structure as message.
			 *
			 * \exception	Decent::Net::Exception	It's thrown when the operation is failed.
			 *
			 * \tparam	T	Generic type parameter.
			 * \param [in,out]	connectionPtr	The connection pointer (must not null).
			 * \param 		  	buf			 	The structure to be sent.
			 */
			template<typename T>
			void SendStruct(ConnectionBase& connectionPtr, const T& buf)
			{
				SetConnectionPtr(connectionPtr);
				return SendStruct(buf);
			}

			/**
			 * \brief	Sends a package of message. The size of the package is sent first, so that receiver
			 * 			can distinguish different packages.
			 *
			 * \exception	Decent::Net::Exception	It's thrown when the operation is failed.
			 *
			 * \param	dataPtr	The data pointer.
			 * \param	size   	The size.
			 */
			virtual void SendPack(const void* const buf, const size_t size)
			{
				uint64_t packSize = size;
				SendRawAll(&packSize, sizeof(packSize));
				SendRawAll(buf, packSize);
			}

			/**
			 * \brief	Sends a package of message. The size of the package is sent first, so that receiver
			 * 			can distinguish different packages.
			 *
			 * \exception	Decent::Net::Exception	It's thrown when the operation is failed.
			 *
			 * \param [in,out]	connectionPtr	The connection pointer. Must not null.
			 * \param 		  	buf			 	The pointer to the buffer. Must not null.
			 * \param 		  	size		 	The size.
			 */
			virtual void SendPack(ConnectionBase& connectionPtr, const void* const buf, const size_t size)
			{
				SetConnectionPtr(connectionPtr);
				return SendPack(buf, size);
			}

			/**
			 * \brief	Sends a container.
			 *
			 * \tparam	Container	Type of the container.
			 * \param	cnt	Container to be sent.
			 */
			template<typename Container>
			void SendContainer(const Container& cnt)
			{
				SendPack(ArrayPtrAndSize::GetPtr(cnt), ArrayPtrAndSize::GetSize(cnt));
			}

			/**
			 * \brief	Sends a container.
			 *
			 * \tparam	Container	Type of the container.
			 * \param [in,out]	connectionPtr	The connection pointer. Must not null.
			 * \param 		  	cnt			 	Container to be sent.
			 */
			template<typename Container>
			void SendContainer(ConnectionBase& connectionPtr, const Container& cnt)
			{
				SendPack(connectionPtr, ArrayPtrAndSize::GetPtr(cnt), ArrayPtrAndSize::GetSize(cnt));
			}

			/**
			 * \brief	Sends a RPC
			 *
			 * \exception	Decent::Net::Exception	It's thrown when the operation is failed.
			 *
			 * \param	rpc	The RPC.
			 */
			virtual void SendRpc(const RpcWriter& rpc)
			{
				if (rpc.HasSizeAtFront())
				{
					const auto& bin = rpc.GetFullBinary();
					SendRawAll(bin.data(), bin.size());
				}
				else
				{
					SendContainer(rpc.GetFullBinary());
				}
			}

			/**
			 * \brief	Sends a RPC
			 *
			 * \exception	Decent::Net::Exception	It's thrown when the operation is failed.
			 *
			 * \param [in,out]	connectionPtr	The connection pointer. Must not null.
			 * \param 		  	rpc			 	The RPC.
			 */
			virtual void SendRpc(ConnectionBase& connectionPtr, const RpcWriter& rpc)
			{
				SetConnectionPtr(connectionPtr);
				return SendRpc(rpc);
			}

			//#################################################
			//#      Receivers
			//#################################################

			/**
			 * \brief	Receive a secure message with specific length.
			 *
			 * \exception	Decent::Net::Exception	It's thrown when the operation is failed.
			 *
			 * \param [in,out]	buf 	The pointer to data buffer (must not null).
			 * \param 		  	size	The size of data need to be received.
			 *
			 * \return	A size_t. Size of data that has been received.
			 */
			virtual size_t RecvRaw(void* buf, const size_t size) = 0;

			/**
			 * \brief	Receive a secure message with specific length.
			 *
			 * \exception	Decent::Net::Exception	It's thrown when the operation is failed.
			 *
			 * \param [in,out]	connectionPtr	The connection pointer (must not null).
			 * \param [in,out]	buf			 	The pointer to data buffer (must not null).
			 * \param 		  	size		 	The size of data need to be received.
			 *
			 * \return	A size_t. Size of data that has been received.
			 */
			virtual size_t RecvRaw(ConnectionBase& connectionPtr, void* buf, const size_t size)
			{
				SetConnectionPtr(connectionPtr);
				return RecvRaw(buf, size);
			}

			/**
			 * \brief	Receive raw message. This function will keep calling RecvRaw until entire message has
			 * 			been received. Exceptions from RecvRaw will be thrown directly, thus, it can be
			 * 			stopped by exceptions.
			 *
			 * \exception	Decent::Net::Exception	It's thrown when the operation is failed.
			 *
			 * \param [out]	buf 	The pointer to the buffer. Must not null.
			 * \param 	   	size	The message size.
			 */
			virtual void RecvRawAll(void* const buf, const size_t size)
			{
				size_t byteRecv = 0;
				while (byteRecv < size)
				{
					byteRecv += RecvRaw(static_cast<uint8_t*>(buf) + byteRecv, size - byteRecv);
				}
			}

			/**
			 * \brief	Receive raw message. This function will keep calling RecvRaw until entire message has
			 * 			been received. Exceptions from RecvRaw will be thrown directly, thus, it can be
			 * 			stopped by exceptions.
			 *
			 * \exception	Decent::Net::Exception	It's thrown when the operation is failed.
			 *
			 * \param [in,out]	connectionPtr	The connection pointer. Must not null.
			 * \param [in,out]	buf			 	If non-null, the buffer. Must not null.
			 * \param 		  	size		 	The message size.
			 */
			virtual void RecvRawAll(ConnectionBase& connectionPtr, void* const buf, const size_t size)
			{
				SetConnectionPtr(connectionPtr);
				return RecvRawAll(buf, size);
			}

			/**
			 * \brief	Receive structure as message.
			 *
			 * \exception	Decent::Net::Exception	It's thrown when the operation is failed.
			 *
			 * \tparam	T	Generic type parameter.
			 * \param [out]	st	The structure to be received.
			 */
			template<typename T>
			void RecvStruct(T& st)
			{
				RecvRawAll(&st, sizeof(T));
			}

			/**
			 * \brief	Receive structure as message.
			 *
			 * \exception	Decent::Net::Exception	It's thrown when the operation is failed.
			 *
			 * \tparam	T	Generic type parameter.
			 * \param [in,out]	connectionPtr	The connection pointer (must not null).
			 * \param [out]	  	st			 	The structure to be received.
			 */
			template<typename T>
			void RecvStruct(ConnectionBase& connectionPtr, T& st)
			{
				SetConnectionPtr(connectionPtr);
				return RecvStruct(st);
			}

			/**
			 * \brief	Receive a package of message. It receives the size of the package first, so it knows
			 * 			how much data to receive. Note: The sender must send the size of package first (e.g.
			 * 			by calling SendPack function).
			 *
			 * \exception	Decent::Net::Exception	It's thrown when the operation is failed.
			 *
			 * \param [in,out]	dest	[in,out] The pointer to the destination buffer. Must be null when
			 * 							calling, otherwise, the buffer pointed by the pointer will not be de-
			 * 							allocated. After the function call, the pointer to new destination buffer
			 * 							will be assigned.
			 *
			 * \return	A size_t. The size of the package.
			 */
			virtual size_t RecvPack(char*& dest)
			{
				uint64_t packSize = 0;
				RecvRawAll(&packSize, sizeof(packSize));

				dest = new char[static_cast<size_t>(packSize)];
				RecvRawAll(dest, static_cast<size_t>(packSize));
				return static_cast<size_t>(packSize);
			}

			/**
			 * \brief	Receive a package of message. It receives the size of the package first, so it knows
			 * 			how much data to receive. Note: The sender must send the size of package first (e.g.
			 * 			by calling SendPack function).
			 *
			 * \exception	Decent::Net::Exception	It's thrown when the operation is failed.
			 *
			 * \param [in,out]	dest	[in,out] The pointer to the destination buffer. Must be null when
			 * 							calling, otherwise, the buffer pointed by the pointer will not be de-
			 * 							allocated. After the function call, the pointer to new destination buffer
			 * 							will be assigned.
			 *
			 * \return	A size_t. The size of the package.
			 */
			virtual size_t RecvPack(ConnectionBase& connectionPtr, char*& dest)
			{
				SetConnectionPtr(connectionPtr);
				return RecvPack(dest);
			}

			/**
			 * \brief	Receives a container.
			 *
			 * \exception	Decent::Net::Exception	It's thrown when the operation is failed.
			 *
			 * \tparam	Container	Type of the container.
			 *
			 * \return	A Container.
			 */
			template<typename Container>
			Container RecvContainer()
			{
				using namespace ArrayPtrAndSize;
				uint64_t packSize = 0;
				RecvRawAll(&packSize, sizeof(packSize));
				
				Container cnt;
				Resize(cnt, static_cast<size_t>(packSize));
				RecvRawAll(GetPtr(cnt), GetSize(cnt));

				return cnt;
			}

			/**
			 * \brief	Receives a container.
			 *
			 * \exception	Decent::Net::Exception	It's thrown when the operation is failed.
			 *
			 * \tparam	Container	Type of the container.
			 *
			 * \return	A Container.
			 */
			template<typename Container>
			Container RecvContainer(ConnectionBase& connectionPtr)
			{
				SetConnectionPtr(connectionPtr);
				return RecvContainer<Container>();
			}
		};
	}
}
