#pragma once

#include <memory>

#include "ObjBase.h"

typedef struct mbedtls_ssl_ticket_context mbedtls_ssl_ticket_context;
typedef struct mbedtls_ssl_session mbedtls_ssl_session;

namespace Decent
{
	namespace MbedTlsObj
	{
		class Drbg;

		class SessionTicketMgrBase
		{
		public: //static member:

			/**
			 * \brief	Parses callback function, used for giving callback functions to the mbedTLS library
			 *
			 * \param [in,out]	p_ticket	The pointer to the SessionTicketMgr object. Must not null.
			 * \param [in,out]	session 	The pointer to the mbedTls SSL session object.
			 * \param [in,out]	buf			Start of the buffer containing the ticket.
			 * \param 		  	len			Length of the ticket.
			 *
			 * \return	mbedTLS errorcode.
			 */
			static int Parse(void *p_ticket, mbedtls_ssl_session *session, unsigned char *buf, size_t len) noexcept;

			/**
			 * \brief	Writes callback function, used for giving callback functions to the mbedTLS library
			 *
			 * \param [in,out]	p_ticket	The pointer to the SessionTicketMgr object. Must not null.
			 * \param 		  	session 	The pointer to the mbedTls SSL session object.
			 * \param [in,out]	start   	Start of the output buffer.
			 * \param 		  	end			End of the output buffer.
			 * \param [in,out]	tlen		On exit, holds the length written.
			 * \param [in,out]	lifetime	On exit, holds the lifetime of the ticket in seconds.
			 *
			 * \return	mbedTLS errorcode.
			 */
			static int Write(void *p_ticket, const mbedtls_ssl_session *session, unsigned char *start, const unsigned char *end, size_t *tlen, uint32_t *lifetime) noexcept;

		public:
			SessionTicketMgrBase() = default;

			virtual ~SessionTicketMgrBase() {}

			virtual void Parse(mbedtls_ssl_session & session, uint8_t* buf, size_t len) = 0;

			virtual void Write(const mbedtls_ssl_session & session, uint8_t* start, const uint8_t* end, size_t& tlen, uint32_t& lifetime) = 0;

		};

		class SessionTicketMgr : public ObjBase<mbedtls_ssl_ticket_context>, virtual public SessionTicketMgrBase
		{
		public: //static members:
			/**
			* \brief	Function that frees MbedTLS object and delete the pointer.
			*
			* \param [in,out]	ptr	If non-null, the pointer.
			*/
			static void FreeObject(mbedtls_ssl_ticket_context* ptr);

		public:

			/**
			 * \brief	Default constructor. Construct a default session ticket manager (Default DRBG, AES-
			 * 			256-GCM, Default ticket lifetime).
			 */
			SessionTicketMgr();

			/** \brief	Destructor */
			virtual ~SessionTicketMgr();

			SessionTicketMgr(SessionTicketMgr&&) = delete;

			SessionTicketMgr(const SessionTicketMgr&) = delete;

			SessionTicketMgr& operator=(SessionTicketMgr&&) = delete;

			SessionTicketMgr& operator=(const SessionTicketMgr&) = delete;

			/**
			 * \brief	Parses
			 *
			 * \exception	MbedTlsException	Error return by mbedTLS C function calls.
			 *
			 * \param [in,out]	session	mbedTls SSL session object.
			 * \param [in,out]	buf	   	Start of the buffer containing the ticket.
			 * \param 		  	len	   	Length of the ticket.
			 */
			virtual void Parse(mbedtls_ssl_session & session, uint8_t* buf, size_t len) override;

			/**
			 * \brief	Writes
			 *
			 * \exception	MbedTlsException	Error return by mbedTLS C function calls.
			 *
			 * \param 		  	session 	mbedTls SSL session object.
			 * \param [in,out]	start   	Start of the output buffer.
			 * \param 		  	end			End of the output buffer.
			 * \param [in,out]	tlen		On exit, holds the length written.
			 * \param [in,out]	lifetime	On exit, holds the lifetime of the ticket in seconds.
			 */
			virtual void Write(const mbedtls_ssl_session & session, uint8_t* start, const uint8_t* end, size_t& tlen, uint32_t& lifetime) override;

			/**
			 * \brief	Query if the pointers to objects held by this object is null
			 *
			 * \return	True if null, false if not.
			 */
			virtual bool IsNull() const noexcept;

		private:
			std::unique_ptr<Drbg> m_rng;
		};
	}
}