#pragma once

#include <utility>
#include <memory>

#include "../../Common/Net/AesGcmCommLayer.h"

typedef struct _sgx_dh_session_enclave_identity_t sgx_dh_session_enclave_identity_t;

namespace Decent
{
	namespace Sgx
	{
		struct LocAttSession
		{
			G128BitSecretKeyWrap m_aek;

			std::unique_ptr<sgx_dh_session_enclave_identity_t> m_id;
		};

		class LocAttCommLayer : public Decent::Net::AesGcmCommLayer
		{
		public:
			LocAttCommLayer() = delete;

			/**
			 * \brief	Constructor. This will call Handshake to perform the local attestation.
			 *
			 * \exception	Decent::RuntimeException	This is thrown if the connection fails, received
			 * message has invalid length, or the SGX SDK failed to process the message.
			 *
			 * \param [in,out]	connectionPtr	The connection pointer that provides connection to the peer.
			 * \param 		  	isInitiator  	True if is initiator, false if not.
			 */
			LocAttCommLayer(Decent::Net::ConnectionBase& cnt, bool isInitiator);

			LocAttCommLayer(const LocAttCommLayer& other) = delete;

			/**
			 * \brief	Move constructor
			 *
			 * \param [in,out]	other	The other.
			 */
			LocAttCommLayer(LocAttCommLayer&& other);

			/** \brief	Destructor */
			virtual ~LocAttCommLayer();

			/**
			 * \brief	Check if this instance is valid (i.e. has not null ptr to identity). It also checks
			 * 			the validity in terms of base class.
			 *
			 * \return	The result of the operation.
			 */
			virtual bool IsValid() const override;

			/**
			 * \brief	Gets the identity
			 *
			 * \return	The identity.
			 */
			const sgx_dh_session_enclave_identity_t& GetIdentity() const;

		private:

			/**
			 * \brief	Constructor that accept the result of the local attestation.
			 *
			 * \param 		  	session	The LA session (after handshake).
			 * \param [in,out]	cnt	   	Network connection.
			 */
			LocAttCommLayer(std::unique_ptr<LocAttSession> session, Net::ConnectionBase& cnt);

			/**
			 * \brief	Perform the handshakes procedure (i.e. local attestation).
			 *
			 * \param [in,out]	cnt		   	The connection to the peer.
			 * \param 		  	isInitiator	True if is initiator, false if not.
			 *
			 * \return	A std::unique_ptr&lt;LocAttSession&gt;
			 */
			std::unique_ptr<LocAttSession> Handshake(Decent::Net::ConnectionBase& cnt, bool isInitiator);

			/**
			 * \brief	Perform the handshakes procedure in initiator side.
			 *
			 * \param [in,out]	cnt	The connection to the peer.
			 *
			 * \return	A std::unique_ptr&lt;LocAttSession&gt;
			 */
			static std::unique_ptr<LocAttSession> InitiatorHandshake(Decent::Net::ConnectionBase& cnt);

			/**
			 * \brief	Perform the handshakes procedure in responder side.
			 *
			 * \param [in,out]	cnt	The connection to the peer.
			 *
			 * \return	A std::unique_ptr&lt;LocAttSession&gt;
			 */
			static std::unique_ptr<LocAttSession> ResponderHandshake(Decent::Net::ConnectionBase& cnt);

			std::unique_ptr<LocAttSession> m_session;
		};
	}
}
