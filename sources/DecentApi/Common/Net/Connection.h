#pragma once

#include <cstdint>

#include <vector>
#include <string>
#include <exception>

namespace Decent
{
	namespace Net
	{
		namespace StatConnection
		{
			/**
			 * \brief	Sends a pack of message
			 *
			 * \exception Decent::Net::Exception
			 *
			 * \param [in,out]	connection	The connection pointer (must not null).
			 * \param 		  	data	  	The pointer to data buffer (must not null).
			 * \param 		  	dataLen   	Length of the data.
			 */
			void SendPack(void* const connection, const void* const data, const size_t dataLen);

			/**
			 * \brief	Sends a pack of message
			 *
			 * \exception Decent::Net::Exception
			 *
			 * \param [in,out]	connection	The connection pointer (must not null).
			 * \param 		  	inMsg	  	Message to be sent.
			 */
			inline void SendPack(void* const connection, const std::string& inMsg)
			{
				SendPack(connection, inMsg.data(), inMsg.size());
			}

			/**
			 * \brief	Receives a pack of message
			 *
			 * \exception Decent::Net::Exception
			 *
			 * \param [in,out]	connection	The connection pointer (must not null).
			 * \param [in,out]	outMsg	  	Received message.
			 */
			void ReceivePack(void* const connection, std::string& outMsg);

			/**
			 * \brief	Sends a pack of message
			 *
			 * \exception Decent::Net::Exception
			 *
			 * \param [in,out]	connection	The connection pointer (must not null).
			 * \param 		  	inMsg	  	Message to be sent.
			 */
			inline void SendPack(void* const connection, const std::vector<uint8_t>& inMsg)
			{
				SendPack(connection, inMsg.data(), inMsg.size());
			}

			/**
			 * \brief	Receives a pack of message
			 *
			 * \exception Decent::Net::Exception
			 *
			 * \param [in,out]	connection	The connection pointer (must not null).
			 * \param [in,out]	outMsg	  	Received message.
			 */
			void ReceivePack(void* const connection, std::vector<uint8_t>& outMsg);

			/**
			 * \brief	Sends and receives a pack of message
			 *
			 * \exception Decent::Net::Exception
			 *
			 * \param [in,out]	connection	The connection pointer (must not null).
			 * \param 		  	inData	  	The pointer to data buffer (must not null).
			 * \param 		  	inDataLen 	Length of the input data.
			 * \param [in,out]	outMsg	  	Received message.
			 */
			void SendAndReceivePack(void* const connection, const void* const inData, const size_t inDataLen, std::string& outMsg);

			/**
			 * \brief	Sends and receives a pack of message
			 *
			 * \exception Decent::Net::Exception
			 *
			 * \param [in,out]	connection	The connection pointer (must not null).
			 * \param 		  	inMsg	  	Message to be sent.
			 * \param [in,out]	outMsg	  	Received message.
			 */
			inline void SendAndReceivePack(void* const connection, const std::string& inMsg, std::string& outMsg)
			{
				SendAndReceivePack(connection, inMsg.data(), inMsg.size(), outMsg);
			}

			/**
			 * \brief	Sends a message with specific length. It's not guaranteed that the entire message will be sent out.
			 * 			The return value says how many data has been sent.
			 *
			 * \exception Decent::Net::Exception
			 *
			 * \param [in,out]	connection	The connection pointer (must not null).
			 * \param 		  	data	  	The pointer to data buffer (must not null).
			 * \param 		  	dataLen   	Length of the data.
			 *
			 * \return	Length of the data that has been sent.
			 */
			size_t SendRaw(void* const connection, const void* const data, const size_t dataLen);

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
			inline int SendRawCallback(void* const connection, const void* const data, const size_t dataLen) noexcept
			{
				try
				{
					return static_cast<int>(SendRaw(connection, data, dataLen));
				}
				catch (const std::exception&)
				{
					return -1;
				}
			}

			/**
			 * \brief	Receives a message with specific length. It's not guaranteed that the entire message
			 * 			with requested length will be received. The return value says how many data has been
			 * 			received.
			 *
			 * \exception	Decent::Net::Exception	.
			 *
			 * \param [in,out]	connection	The connection pointer (must not null).
			 * \param [in,out]	buf		  	The pointer to data buffer (must not null).
			 * \param 		  	bufLen	  	Length of the buffer.
			 *
			 * \return	Length of the data that has been received.
			 */
			size_t ReceiveRaw(void* const connection, void* const buf, const size_t bufLen);

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
			inline int ReceiveRawCallback(void* const connection, void* const buf, const size_t bufLen) noexcept
			{
				try
				{
					return static_cast<int>(ReceiveRaw(connection, buf, bufLen));
				}
				catch (const std::exception&)
				{
					return -1;
				}
			}
		}
	}
}
