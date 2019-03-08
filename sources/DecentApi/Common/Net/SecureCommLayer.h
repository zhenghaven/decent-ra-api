#pragma once

#include <string>

namespace Decent
{
	namespace Net
	{
		class SecureCommLayer
		{
		public:
			SecureCommLayer() = default;

			virtual ~SecureCommLayer() {}

			/**
			 * \brief	Sends a secure message with specific length. It's guaranteed that after this call,
			 * 			entire message will be sent.
			 *
			 * \exception	Decent::Net::Exception	.
			 *
			 * \param [in,out]	connectionPtr	The connection pointer (must not null).
			 * \param 		  	buf			 	The pointer to data buffer (must not null).
			 * \param 		  	size		 	Size of the data.
			 */
			virtual void SendRaw(void* const connectionPtr, const void* buf, const size_t size) = 0;

			/**
			 * \brief	Receive a secure message with specific length. It's guaranteed that after this call,
			 * 			entire message will be received. Note: If the message received doesn't match the size
			 * 			requested, exception will be thrown!
			 *
			 * \exception	Decent::Net::Exception	.
			 *
			 * \param [in,out]	connectionPtr	The connection pointer (must not null).
			 * \param [in,out]	buf			 	The pointer to data buffer (must not null).
			 * \param 		  	size		 	The size of data need to be received.
			 */
			virtual void ReceiveRaw(void* const connectionPtr, void* buf, const size_t size) = 0;

			/**
			 * \brief	Sends a structure as message.
			 *
			 * \tparam	T	Generic type parameter.
			 * \param [in,out]	connectionPtr	The connection pointer (must not null).
			 * \param 		  	buf			 	The structure to be sent.
			 */
			template<typename T>
			void SendStruct(void* const connectionPtr, const T& buf)
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
			void ReceiveStruct(void* const connectionPtr, T& buf)
			{
				ReceiveRaw(connectionPtr, &buf, sizeof(T));
			}

			/**
			 * \brief	Sends a message.
			 *
			 * \param [in,out]	connectionPtr	The connection pointer (must not null).
			 * \param 		  	inMsg		 	Message to be sent.
			 */
			virtual void SendMsg(void* const connectionPtr, const std::string& inMsg) = 0;

			/**
			 * \brief	Receives a message. Output message size will be automatically adjusted to fit the
			 * 			message received.
			 *
			 * \param [in,out]	connectionPtr	If non-null, the connection pointer.
			 * \param [in,out]	outMsg		 	Received message.
			 */
			virtual void ReceiveMsg(void* const connectionPtr, std::string& outMsg) = 0;

			/**
			 * \brief	Determine this instance is in valid or not.
			 *
			 * \return	True if valid, otherwise, false.
			 */
			virtual operator bool() const = 0;
		};
	}
}
