#pragma once

#include "SecureCommLayer.h"

#include "../GeneralKeyTypes.h"

namespace Decent
{
	namespace Net
	{
		/** \brief	The communications layer that uses 128-bit AES-GCM encryption. */
		class AesGcmCommLayer : virtual public SecureCommLayer
		{
		public: //static members:
			typedef G128BitSecretKeyWrap KeyType;

		public:
			AesGcmCommLayer() = delete;

			/**
			 * \brief	Constructor
			 *
			 * \param	sKey	128-bit key used for AES-GCM encryption.
			 */
			AesGcmCommLayer(const KeyType& sKey, const KeyType& mKey, ConnectionBase* connection);

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
			virtual bool IsValid() const;

			using SecureCommLayer::SendRaw;
			virtual size_t SendRaw(const void* buf, const size_t size) override;

			using SecureCommLayer::RecvRaw;
			virtual size_t RecvRaw(void* buf, const size_t size) override;

			virtual void SetConnectionPtr(ConnectionBase& cnt) override;

		private: // Methods:

			/**
			 * \brief	Decrypts a message into binary
			 *
			 * \param 	inMsg	Input message (cipher text).
			 *
			 * \return	Output message in binary (plain text).
			 */
			virtual std::vector<uint8_t> DecryptMsg(const std::vector<uint8_t>& inMsg);

			/**
			 * \brief	Encrypts a message into binary
			 *
			 * \exception Decent::Net::Exception
			 *
			 * \param 	inMsg	Input message (plain text).
			 *
			 * \return	Output message in binary (cipher text).
			 */
			virtual std::vector<uint8_t> EncryptMsg(const std::vector<uint8_t>& inMsg);


		private:
			KeyType m_sKey; //Secret Key
			KeyType m_mKey; //Masking Key

			ConnectionBase* m_connection;

			std::vector<uint8_t> m_streamBuf;
		};
	}
}
