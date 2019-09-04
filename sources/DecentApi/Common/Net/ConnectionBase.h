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
		public: //static members:
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

		public:

			/** \brief	Default constructor */
			ConnectionBase() = default;

			/** \brief	Destructor */
			virtual ~ConnectionBase() {}

			//#################################################
			//#      Senders
			//#################################################

			/**
			 * \brief	Sends raw data.
			 *
			 * \exception	Decent::Net::Exception	.
			 *
			 * \param	dataPtr	The data pointer.
			 * \param	size   	The size.
			 *
			 * \return	A size_t. The size of data has been sent.
			 */
			virtual size_t SendRaw(const void* const dataPtr, const size_t size) = 0;

			/**
			 * \brief	Sends a raw message. This function will keep calling SendRaw until entire message has
			 * 			been sent out. Exceptions from SendRaw will not be caught, thus, it can be stopped by
			 * 			exceptions.
			 *
			 * \exception	Decent::Net::Exception	.
			 *
			 * \param	dataPtr	The data pointer.
			 * \param	size   	The size.
			 */
			virtual void SendRawGuarantee(const void* const dataPtr, const size_t size)
			{
				size_t sentSize = 0;
				while (sentSize < size)
				{
					sentSize += SendRaw(static_cast<const uint8_t*>(dataPtr) + sentSize, size - sentSize);
				}
			}

			/**
			 * \brief	Sends a package of message. The size of the package is sent first, so that receiver
			 * 			can distinguish different packages.
			 *
			 * \exception	Decent::Net::Exception	.
			 *
			 * \param	dataPtr	The data pointer.
			 * \param	size   	The size.
			 */
			virtual void SendPack(const void* const dataPtr, const size_t size)
			{
				uint64_t packSize = size;
				SendRawGuarantee(&packSize, sizeof(uint64_t));
				SendRawGuarantee(dataPtr, packSize);
			}

			/**
			 * \brief	Sends a package of message. The size of the package is sent first, so that receiver
			 * 			can distinguish different packages.
			 *
			 * \exception	Decent::Net::Exception	.
			 *
			 * \tparam	Container	Type of the container.
			 * \param	msg	The message.
			 */
			template<typename Container>
			void SendPack(const Container& msg)
			{
				SendPack(ArrayPtrAndSize::GetPtr(msg), ArrayPtrAndSize::GetSize(msg));
			}

			//#################################################
			//#      Receivers
			//#################################################

			/**
			 * \brief	Receive raw data
			 *
			 * \exception	Decent::Net::Exception	.
			 *
			 * \param [in,out]	bufPtr	The buffer pointer. Must not null!
			 * \param 		  	size  	The size.
			 *
			 * \return	A size_t. The size of data has been received.
			 */
			virtual size_t ReceiveRaw(void* const bufPtr, const size_t size) = 0;

			/**
			 * \brief	Receive raw message. This function will keep calling ReceiveRaw until entire message
			 * 			has been received. Exceptions from ReceiveRaw will not be caught, thus, it can be
			 * 			stopped by exceptions.
			 *
			 * \exception	Decent::Net::Exception	.
			 *
			 * \param [out]	bufPtr	The buffer pointer. Must not null!
			 * \param 	   	size  	The message size.
			 */
			virtual void ReceiveRawGuarantee(void* const bufPtr, const size_t size)
			{
				size_t recvSize = 0;
				while (recvSize < size)
				{
					recvSize += ReceiveRaw(static_cast<uint8_t*>(bufPtr) + recvSize, size - recvSize);
				}
			}

			/**
			 * \brief	Receive a package of message. It receives the size of the package first, so it knows
			 * 			how much data to receive. Note: The sender must send the size of package first (e.g.
			 * 			by calling SendPack function).
			 *
			 * \exception	Decent::Net::Exception	.
			 *
			 * \param [in,out]	dest	[in,out] The pointer to the destination buffer. Must be null when
			 * 							calling, otherwise, the buffer pointed by the pointer will not be de-
			 * 							allocated. After the function call, the pointer to new destination buffer
			 * 							will be assigned.
			 *
			 * \return	A size_t. The size of the package.
			 */
			virtual size_t ReceivePack(char*& dest)
			{
				uint64_t packSize = 0;
				ReceiveRawGuarantee(&packSize, sizeof(packSize));

				dest = new char[static_cast<size_t>(packSize)];
				ReceiveRawGuarantee(dest, static_cast<size_t>(packSize));
				return static_cast<size_t>(packSize);
			}

			/**
			 * \brief	Receive pack
			 *
			 * \exception	Decent::Net::Exception	.
			 *
			 * \param [out]	outMsg	Output message.
			 */
			virtual void ReceivePack(std::string& outMsg)
			{
				uint64_t packSize = 0;
				ReceiveRawGuarantee(&packSize, sizeof(packSize));

				outMsg.resize(static_cast<size_t>(packSize));
				ReceiveRawGuarantee(&outMsg[0], outMsg.size());
			}

			/**
			 * \brief	Receive pack
			 *
			 * \exception	Decent::Net::Exception	.
			 *
			 * \param [out]	outBin	Output binary.
			 */
			virtual void ReceivePack(std::vector<uint8_t>& outBin)
			{
				uint64_t packSize = 0;
				ReceiveRawGuarantee(&packSize, sizeof(packSize));

				outBin.resize(static_cast<size_t>(packSize));
				ReceiveRawGuarantee(&outBin[0], outBin.size());
			}

			/**
			 * \brief	Receive message.
			 *
			 * \exception	Decent::Net::Exception	.
			 *
			 * \return	A std::string.
			 */
			virtual std::string RecvMsg()
			{
				std::string msg;
				ReceivePack(msg);
				return msg;
			}

			/**
			 * \brief	Receive binary.
			 *
			 * \exception	Decent::Net::Exception	.
			 *
			 * \return	A std::vector&lt;uint8_t&gt;
			 */
			virtual std::vector<uint8_t> RecvBin()
			{
				std::vector<uint8_t> bin;
				ReceivePack(bin);
				return bin;
			}

			//#################################################
			//#      Mix of sender and receiver
			//#################################################

			/**
			 * \brief	Sends a package of message, and then receive a package of message.
			 *
			 * \param 	   	inData   	Information describing the in.
			 * \param 	   	inDataLen	Length of the in data.
			 * \param [out]	outMsg   	Output message.
			 */
			virtual void SendAndReceivePack(const void* const inData, const size_t inDataLen, std::string& outMsg)
			{
				SendPack(inData, inDataLen);
				ReceivePack(outMsg);
			}

			/**
			 * \brief	Sends a package of message, and then receive a package of message.
			 *
			 * \tparam	Container	Type of the container.
			 * \param 	   	inMsg 	Message describing the in.
			 * \param [out]	outMsg	Output message.
			 */
			template<typename Container>
			void SendAndReceivePack(const Container& inMsg, std::string& outMsg)
			{
				SendAndReceivePack(ArrayPtrAndSize::GetPtr(inMsg), ArrayPtrAndSize::GetSize(inMsg), outMsg);
			}

			/** \brief	Terminates this connection */
			virtual void Terminate() noexcept = 0;
		};

	}
}
