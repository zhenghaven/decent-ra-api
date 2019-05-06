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
			AesGcmCommLayer(const uint8_t(&sKey)[GENERAL_128BIT_16BYTE_SIZE], ConnectionBase* connection);

			/**
			 * \brief	Constructor
			 *
			 * \param	sKey	128-bit key used for AES-GCM encryption.
			 */
			AesGcmCommLayer(const AesGcm128bKeyType& sKey, ConnectionBase* connection);

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
			 * \brief	Decrypts a message into binary.
			 *
			 * \exception Decent::Net::Exception
			 *
			 * \param	inMsg 	Input message (cipher text).
			 * \param	inSize	Message length.
			 *
			 * \return	Output message in binary (plain text).
			 */
			virtual std::vector<uint8_t> DecryptBin(const void* inMsg, const size_t inSize);

			/**
			 * \brief	Encrypts a message into binary.
			 *
			 * \exception Decent::Net::Exception
			 *
			 * \param	inMsg 	Input message (plain text).
			 * \param	inSize	Message length.
			 *
			 * \return	Output message in binary (cipher text).
			 */
			virtual std::vector<uint8_t> EncryptBin(const void* inMsg, const size_t inSize);

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
			 * \param 	inMsg	Input message (plain text).
			 *
			 * \return	Output message (cipher text).
			 */
			virtual std::string EncryptMsg(const std::string& inMsg)
			{
				return EncryptMsg(inMsg.data(), inMsg.size());
			}

			/**
			 * \brief	Decrypts a message into binary
			 *
			 * \param 	inMsg	Input message (cipher text).
			 *
			 * \return	Output message in binary (plain text).
			 */
			virtual std::vector<uint8_t> DecryptMsg(const std::vector<uint8_t>& inMsg)
			{
				return DecryptBin(inMsg.data(), inMsg.size());
			}

			/**
			 * \brief	Encrypts a message into binary
			 *
			 * \exception Decent::Net::Exception
			 *
			 * \param 	inMsg	Input message (plain text).
			 *
			 * \return	Output message in binary (cipher text).
			 */
			virtual std::vector<uint8_t> EncryptMsg(const std::vector<uint8_t>& inMsg)
			{
				return EncryptBin(inMsg.data(), inMsg.size());
			}

			virtual void ReceiveRaw(void* buf, const size_t size) override;
			virtual void ReceiveRaw(ConnectionBase& cnt, void* buf, const size_t size) override
			{
				SecureCommLayer::ReceiveRaw(cnt, buf, size);
			}

			virtual void SendRaw(const void* buf, const size_t size) override;
			virtual void SendRaw(ConnectionBase& cnt, const void* buf, const size_t size) override
			{
				SecureCommLayer::SendRaw(cnt, buf, size);
			}

			virtual void SendMsg(const std::string& inMsg) override
			{
				SendRaw(inMsg.data(), inMsg.size());
			}
			virtual void SendMsg(ConnectionBase& cnt, const std::string& inMsg) override
			{
				SecureCommLayer::SendMsg(cnt, inMsg);
			}

			virtual void ReceiveMsg(std::string& outMsg) override;
			virtual void ReceiveMsg(ConnectionBase& cnt, std::string& outMsg) override
			{
				SecureCommLayer::ReceiveMsg(cnt, outMsg);
			}

			virtual void SendMsg(const std::vector<uint8_t>& inMsg) override
			{
				SendRaw(inMsg.data(), inMsg.size());
			}
			virtual void SendMsg(ConnectionBase& cnt, const std::vector<uint8_t>& inMsg) override
			{
				SecureCommLayer::SendMsg(cnt, inMsg);
			}

			virtual void ReceiveMsg(std::vector<uint8_t>& outMsg) override;
			virtual void ReceiveMsg(ConnectionBase& cnt, std::vector<uint8_t>& outMsg) override
			{
				SecureCommLayer::ReceiveMsg(cnt, outMsg);
			}

			virtual void SetConnectionPtr(ConnectionBase& cnt) override;

		private:
			GcmObjType m_gcm;
			ConnectionBase* m_connection;
		};
	}
}
