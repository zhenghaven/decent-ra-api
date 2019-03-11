#pragma once

#include "SecureCommLayer.h"

#include <memory>

#include "../GeneralKeyTypes.h"
#include "../MbedTls/Gcm.h"

namespace Decent
{
	namespace Net
	{
		/** \brief	The communications layer that uses 128-bit AES-GCM encryption. */
		class AesGcmCommLayer : virtual public SecureCommLayer
		{
		public:
			typedef General128BitKey AesGcm128bKeyType;
			typedef MbedTlsObj::Gcm<16, MbedTlsObj::GcmBase::Cipher::AES> GcmObjType;

		public:
			AesGcmCommLayer() = delete;

			/**
			 * \brief	Constructor
			 *
			 * \param	sKey	128-bit key used for AES-GCM encryption.
			 */
			AesGcmCommLayer(const uint8_t(&sKey)[GENERAL_128BIT_16BYTE_SIZE]);

			/**
			 * \brief	Constructor
			 *
			 * \param	sKey	128-bit key used for AES-GCM encryption.
			 */
			AesGcmCommLayer(const AesGcm128bKeyType& sKey);

			//Copy is prohibited. 
			AesGcmCommLayer(const AesGcmCommLayer& other) = delete;

			/**
			 * \brief	Move constructor
			 *
			 * \param [in,out]	other	The other.
			 */
			AesGcmCommLayer(AesGcmCommLayer&& other);

			/** \brief	Destructor */
			virtual ~AesGcmCommLayer();

			//Copy is prohibited. 
			AesGcmCommLayer& operator=(const AesGcmCommLayer& other) = delete;

			/**
			 * \brief	Move assignment operator
			 *
			 * \exception Decent::Net::Exception
			 *
			 * \param [in,out]	other	The other.
			 *
			 * \return	A reference to this object.
			 */
			AesGcmCommLayer& operator=(AesGcmCommLayer&& other);

			/**
			 * \brief	Check if this instance is valid (i.e. the GCM object is set and valid);
			 *
			 * \return	True if is valid, otherwise, false.
			 */
			virtual operator bool() const override;

			/**
			 * \brief	Decrypts a message
			 *
			 * \exception Decent::Net::Exception
			 *
			 * \param	inMsg 	Input message (cipher text).
			 * \param	inSize	Message length.
			 *
			 * \return	Output message (plain text).
			 */
			virtual std::string DecryptMsg(const void* inMsg, const size_t inSize);

			/**
			 * \brief	Decrypts a message
			 *
			 * \param 	inMsg	Input message (cipher text).
			 *
			 * \return	Output message (plain text).
			 */
			virtual std::string DecryptMsg(const std::string& inMsg)
			{
				return DecryptMsg(inMsg.data(), inMsg.size());
			}

			/**
			 * \brief	Encrypts a message
			 *
			 * \exception Decent::Net::Exception
			 *
			 * \param	inMsg 	Input message (plain text).
			 * \param	inSize	Message length.
			 *
			 * \return	Output message (cipher text).
			 */
			virtual std::string EncryptMsg(const void* inMsg, const size_t inSize);

			/**
			 * \brief	Encrypts a message
			 *
			 * \exception Decent::Net::Exception
			 *
			 * \param 	inMsg	Input message (plain text).
			 *
			 * \return	Output message (cipher text).
			 */
			virtual std::string EncryptMsg(const std::string& inMsg)
			{
				return EncryptMsg(inMsg.data(), inMsg.size());
			}
			
			virtual void ReceiveRaw(void* buf, const size_t size) override;
			virtual void ReceiveRaw(void* const connectionPtr, void* buf, const size_t size) override
			{
				SecureCommLayer::ReceiveRaw(connectionPtr, buf, size);
			}

			virtual void SendRaw(const void* buf, const size_t size) override;
			virtual void SendRaw(void* const connectionPtr, const void* buf, const size_t size) override
			{
				SecureCommLayer::SendRaw(connectionPtr, buf, size);
			}

			virtual void SendMsg(const std::string& inMsg) override
			{
				SendRaw(inMsg.data(), inMsg.size());
			}
			virtual void SendMsg(void* const connectionPtr, const std::string& inMsg) override
			{
				SecureCommLayer::SendMsg(connectionPtr, inMsg);
			}

			virtual void ReceiveMsg(std::string& outMsg) override;
			virtual void ReceiveMsg(void* const connectionPtr, std::string& outMsg) override
			{
				SecureCommLayer::ReceiveMsg(connectionPtr, outMsg);
			}

			virtual void SetConnectionPtr(void* const connectionPtr) override;

		private:
			GcmObjType m_gcm;
			void* m_connection;
		};
	}
}
