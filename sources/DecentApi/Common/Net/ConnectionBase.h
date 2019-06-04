#pragma once

#include <string>
#include <vector>
#include <cstdint>

#include "../ArrayPtrAndSize.h"

namespace Decent
{
	namespace Net
	{
		class ConnectionBase
		{
		public:
			ConnectionBase() = default;

			virtual ~ConnectionBase() {}

			virtual size_t SendRaw(const void* const dataPtr, const size_t size) = 0;

			/**
			 * \brief	Sends a raw message. This function will keep calling SendRaw until entire message has
			 * 			been sent out. Exceptions from SendRaw will not be caught, thus, it can be stopped by
			 * 			exceptions.
			 *
			 * \param	dataPtr	The data pointer.
			 * \param	size   	The size.
			 */
			virtual void SendRawGuarantee(const void* const dataPtr, const size_t size);

			virtual void SendPack(const void* const dataPtr, const size_t size);

			template<typename Container>
			void SendPack(const Container& msg)
			{
				SendPack(ArrayPtrAndSize::GetPtr(msg), ArrayPtrAndSize::GetSize(msg));
			}

			//Receivers:
			
			virtual size_t ReceiveRaw(void* const bufPtr, const size_t size) = 0;

			/**
			 * \brief	Receive raw message. This function will keep calling ReceiveRaw until entire message
			 * 			has been received. Exceptions from ReceiveRaw will not be caught, thus, it can be
			 * 			stopped by exceptions.
			 *
			 * \param [out]	bufPtr	If non-null, the buffer pointer.
			 * \param 	   	size  	The message size.
			 */
			virtual void ReceiveRawGuarantee(void* const bufPtr, const size_t size);

			virtual size_t ReceivePack(char*& dest);

			virtual void ReceivePack(std::string& outMsg);

			virtual void ReceivePack(std::vector<uint8_t>& outMsg);


			virtual void SendAndReceivePack(const void* const inData, const size_t inDataLen, std::string& outMsg);

			template<typename Container>
			void SendAndReceivePack(const Container& inMsg, std::string& outMsg)
			{
				SendAndReceivePack(ArrayPtrAndSize::GetPtr(inMsg), ArrayPtrAndSize::GetSize(inMsg), outMsg);
			}

			//For CallBacks:

			/**
			* \brief	Sends a message with specific length, and this function usually is used as callback.
			* 			It's not guaranteed that the entire message will be sent out. The return value says
			* 			how many data has been sent. No exception will be thrown, instead, -1 will be
			* 			returned when a exception get caught.
			*
			* \param [in,out]	connection	The connection pointer (must not null).
			* \param 		  	data	  	The data.
			* \param 		  	dataLen   	Length of the data.
			*
			* \return	Length of the data that has been sent, or -1 when error.
			*/
			static int SendRawCallback(void* const connection, const void* const data, const size_t dataLen) noexcept;

			/**
			* \brief	Receives a message with specific length, and this function usually is used as
			* 			callback. It's not guaranteed that the entire message with requested length will be
			* 			received. The return value says how many data has been received. No exception will be
			* 			thrown, instead, -1 will be returned when a exception get caught.
			*
			* \param [in,out]	connection	The connection pointer (must not null).
			* \param [in,out]	buf		  	The pointer to data buffer (must not null).
			* \param 		  	bufLen	  	Length of the buffer.
			*
			* \return	Length of the data that has been received, or -1 when error.
			*/
			static int ReceiveRawCallback(void* const connection, void* const buf, const size_t bufLen) noexcept;


			/** \brief	Terminates this connection */
			virtual void Terminate() noexcept = 0;
		};

	}
}
