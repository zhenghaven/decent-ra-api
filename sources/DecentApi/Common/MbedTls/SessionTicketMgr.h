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
			static int Parse(void *p_ticket, mbedtls_ssl_session *session, unsigned char *buf, size_t len)
			{
				if (!p_ticket || !session || !buf)
				{
					return -1;
				}

				try
				{
					return static_cast<SessionTicketMgrBase*>(p_ticket)->Parse(*session, static_cast<uint8_t *>(buf), len);
				}
				catch (const std::exception&)
				{
					return -1;
				}
			}

			static int Write(void *p_ticket, const mbedtls_ssl_session *session, unsigned char *start, const unsigned char *end, size_t *tlen, uint32_t *lifetime)
			{
				if (!p_ticket || !session || !start || !end || !tlen || !lifetime)
				{
					return -1;
				}

				try
				{
					return static_cast<SessionTicketMgrBase*>(p_ticket)->Write(*session, 
						static_cast<uint8_t *>(start), static_cast<const uint8_t *>(end), *tlen, *lifetime);
				}
				catch (const std::exception&)
				{
					return -1;
				}
			}

		public:
			SessionTicketMgrBase() = default;

			virtual ~SessionTicketMgrBase() {}

			virtual int Parse(mbedtls_ssl_session & session, uint8_t* buf, size_t len) = 0;

			virtual int Write(const mbedtls_ssl_session & session, uint8_t* start, const uint8_t* end, size_t& tlen, uint32_t& lifetime) = 0;

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
			SessionTicketMgr();

			virtual ~SessionTicketMgr();

			SessionTicketMgr(SessionTicketMgr&&) = delete;

			SessionTicketMgr(const SessionTicketMgr&) = delete;

			SessionTicketMgr& operator=(SessionTicketMgr&&) = delete;

			SessionTicketMgr& operator=(const SessionTicketMgr&) = delete;

			virtual int Parse(mbedtls_ssl_session & session, uint8_t* buf, size_t len) override;

			virtual int Write(const mbedtls_ssl_session & session, uint8_t* start, const uint8_t* end, size_t& tlen, uint32_t& lifetime) override;

		private:
			std::unique_ptr<Drbg> m_rng;
		};
	}
}