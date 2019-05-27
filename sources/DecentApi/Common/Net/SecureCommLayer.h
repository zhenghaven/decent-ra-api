#pragma once

#include <cstdint>

#include <string>
#include <vector>

#include "RpcWriter.h"

namespace Decent
{
	namespace Net
	{
		class ConnectionBase;

		class SecureCommLayer
		{
		public:
			SecureCommLayer() = default;

			virtual ~SecureCommLayer() {}

			/**
			 * \brief	Sends a secure message with specific length. It's guaranteed that after this call,
			 * 			entire message will be sent.
			 *
			 * \exception	Decent::Net::Exception	It's thrown when the operation is failed.
			 *
			 * \param 		  	buf 	The pointer to data buffer (must not null).
			 * \param 		  	size	Size of the data.
			 */
			virtual void SendRaw(const void* buf, const size_t size) = 0;

			/**
			 * \brief	Sends a secure message with specific length. It's guaranteed that after this call,
			 * 			entire message will be sent.
			 *
			 * \exception	Decent::Net::Exception	It's thrown when the operation is failed.
			 *
			 * \param [in,out]	connectionPtr	The connection pointer (must not null).
			 * \param 		  	buf			 	The pointer to data buffer (must not null).
			 * \param 		  	size		 	Size of the data.
			 */
			virtual void SendRaw(ConnectionBase& connectionPtr, const void* buf, const size_t size)
			{
				SetConnectionPtr(connectionPtr);
				SendRaw(buf, size);
			}

			/**
			 * \brief	Receive a secure message with specific length. It's guaranteed that after this call,
			 * 			entire message will be received. Note: If the message received doesn't match the size
			 * 			requested, exception will be thrown!
			 *
			 * \exception	Decent::Net::Exception	It's thrown when the operation is failed.
			 *
			 * \param [in,out]	buf 	The pointer to data buffer (must not null).
			 * \param 		  	size	The size of data need to be received.
			 */
			virtual void ReceiveRaw(void* buf, const size_t size) = 0;

			/**
			 * \brief	Receive a secure message with specific length. It's guaranteed that after this call,
			 * 			entire message will be received. Note: If the message received doesn't match the size
			 * 			requested, exception will be thrown!
			 *
			 * \exception	Decent::Net::Exception	It's thrown when the operation is failed.
			 *
			 * \param [in,out]	connectionPtr	The connection pointer (must not null).
			 * \param [in,out]	buf			 	The pointer to data buffer (must not null).
			 * \param 		  	size		 	The size of data need to be received.
			 */
			virtual void ReceiveRaw(ConnectionBase& connectionPtr, void* buf, const size_t size)
			{
				SetConnectionPtr(connectionPtr);
				ReceiveRaw(buf, size);
			}

			/**
			 * \brief	Sends a RPC
			 *
			 * \param	rpc	The RPC.
			 */
			virtual void SendRpc(const RpcWriter& rpc)
			{
				if (rpc.HasSizeAtFront())
				{
					const auto& bin = rpc.GetBinaryArray();
					SendRaw(bin.data(), bin.size());
				}
				else
				{
					SendMsg(rpc.GetBinaryArray());
				}
			}

			/**
			* \brief	Sends a structure as message.
			*
			* \tparam	T	Generic type parameter.
			* \param 		  	buf			 	The structure to be sent.
			*/
			template<typename T>
			void SendStruct(const T& buf)
			{
				SendRaw(&buf, sizeof(T));
			}

			/**
			* \brief	Receive structure as message.
			*
			* \tparam	T	Generic type parameter.
			* \param [in,out]	buf			 	The structure buffer.
			*/
			template<typename T>
			void ReceiveStruct(T& buf)
			{
				ReceiveRaw(&buf, sizeof(T));
			}

			/**
			 * \brief	Sends a structure as message.
			 *
			 * \tparam	T	Generic type parameter.
			 * \param [in,out]	connectionPtr	The connection pointer (must not null).
			 * \param 		  	buf			 	The structure to be sent.
			 */
			template<typename T>
			void SendStruct(ConnectionBase& connectionPtr, const T& buf)
			{
				SendRaw(connectionPtr, &buf, sizeof(T));
			}

			/**
			 * \brief	Receive structure as message.
			 *
			 * \tparam	T	Generic type parameter.
			 * \param [in,out]	connectionPtr	The connection pointer (must not null).
			 * \param [in,out]	buf			 	The structure buffer.
			 */
			template<typename T>
			void ReceiveStruct(ConnectionBase& connectionPtr, T& buf)
			{
				ReceiveRaw(connectionPtr, &buf, sizeof(T));
			}

			/**
			 * \brief	Sends a message.
			 *
			 * \param 		  	inMsg	Message to be sent.
			 */
			virtual void SendMsg(const std::string& inMsg) = 0;

			/**
			 * \brief	Sends a message.
			 *
			 * \param [in,out]	connectionPtr	The connection pointer (must not null).
			 * \param 		  	inMsg		 	Message to be sent.
			 */
			virtual void SendMsg(ConnectionBase& connectionPtr, const std::string& inMsg)
			{
				SetConnectionPtr(connectionPtr);
				SendMsg(inMsg);
			}

			/**
			 * \brief	Receives a message. Output message size will be automatically adjusted to fit the
			 * 			message received.
			 *
			 * \param [in,out]	outMsg	Received message.
			 */
			virtual void ReceiveMsg(std::string& outMsg) = 0;

			/**
			 * \brief	Receives a message. Output message size will be automatically adjusted to fit the
			 * 			message received.
			 *
			 * \param [in,out]	connectionPtr	The connection pointer.
			 * \param [in,out]	outMsg		 	Received message.
			 */
			virtual void ReceiveMsg(ConnectionBase& connectionPtr, std::string& outMsg)
			{
				SetConnectionPtr(connectionPtr);
				ReceiveMsg(outMsg);
			}

			/**
			 * \brief	Sends a message.
			 *
			 * \param 		  	inMsg	Message to be sent.
			 */
			virtual void SendMsg(const std::vector<uint8_t>& inMsg) = 0;

			/**
			 * \brief	Sends a message.
			 *
			 * \param [in,out]	connectionPtr	The connection pointer (must not null).
			 * \param 		  	inMsg		 	Message to be sent.
			 */
			virtual void SendMsg(ConnectionBase& connectionPtr, const std::vector<uint8_t>& inMsg)
			{
				SetConnectionPtr(connectionPtr);
				SendMsg(inMsg);
			}

			/**
			 * \brief	Receives a binary block.
			 *
			 * \return	A std::vector&lt;uint8_t&gt;
			 */
			virtual std::vector<uint8_t> ReceiveBinary() = 0;

			/**
			 * \brief	Receives a binary block. 
			 *
			 * \param [in,out]	connectionPtr	The connection pointer.
			 *
			 * \return	A std::vector&lt;uint8_t&gt;
			 */
			virtual std::vector<uint8_t> ReceiveBinary(ConnectionBase& connectionPtr)
			{
				SetConnectionPtr(connectionPtr);
				return ReceiveBinary();
			}

			/**
			 * \brief	Determine this instance is in valid or not.
			 *
			 * \return	True if valid, otherwise, false.
			 */
			virtual operator bool() const = 0;

			virtual void SetConnectionPtr(ConnectionBase& connectionPtr) = 0;
		};
	}
}
