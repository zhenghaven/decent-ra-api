#pragma once

#include "SecureCommLayer.h"

#include <memory>

#include <mbedTLScpp/SecretVector.hpp>
#include <mbedTLScpp/SKey.hpp>

#include "../Crypto/AesGcmPacker.hpp"

namespace Decent
{
	namespace Net
	{
		/** \brief	The communications layer that uses 128-bit AES-GCM encryption. */
		class AesGcmCommLayer : public SecureCommLayer
		{
		public: //static members:

			typedef mbedTLScpp::SKey<128> KeyType;

			static constexpr uint64_t sk_maxCounter = std::numeric_limits<uint64_t>::max();

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

		protected: // Methods:

			/**
			 * \brief	Decrypts a message into binary
			 *
			 * \param 	inMsg	Input message (cipher text).
			 *
			 * \return	Output message in binary (plain text).
			 */
			virtual mbedTLScpp::SecretVector<uint8_t> DecryptMsg(const std::vector<uint8_t>& inMsg);

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

			virtual void CheckSelfKeysLifetime();

			virtual void CheckPeerKeysLifetime();

			virtual void RefreshSelfKeys();

			virtual void RefreshPeerKeys();

		private:

			/** \brief	Refresh self add data. USED BY THE CONSTRUCTOR, CANNOT BE VIRTUAL! */
			void RefreshSelfAddData();

			/** \brief	Refresh peer add data. USED BY THE CONSTRUCTOR, CANNOT BE VIRTUAL! */
			void RefreshPeerAddData();

		private:
			KeyType m_selfSecKey; //Secret Key
			KeyType m_selfMakKey; //Masking Key
			mbedTLScpp::SecretArray<uint64_t, 3> m_selfAddData; //Additonal Data for MAC (m_selfMakKey || MsgCounter)
			std::unique_ptr<Crypto::AesGcmPacker> m_selfAesGcm;

			KeyType m_peerSecKey; //Secret Key
			KeyType m_peerMakKey; //Masking Key
			mbedTLScpp::SecretArray<uint64_t, 3> m_peerAddData; //Additonal Data for MAC (m_peerMakKey || MsgCounter)
			std::unique_ptr<Crypto::AesGcmPacker> m_peerAesGcm;

			ConnectionBase* m_connection;

			mbedTLScpp::SecretVector<uint8_t> m_streamBuf;
		};
	}
}
