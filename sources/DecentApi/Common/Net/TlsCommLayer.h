#pragma once

#include "SecureCommLayer.h"

#include <memory>

#include <mbedTLScpp/Tls.hpp>

#include "../Exceptions.h"
#include "ConnectionBase.h"

namespace Decent
{
	namespace Net
	{
		class TlsInnerConn
		{
		public:
			TlsInnerConn(ConnectionBase* conn) :
				m_conn(conn)
			{}

			virtual ~TlsInnerConn()
			{}

			void SetConnPtr(ConnectionBase* conn)
			{
				m_conn = conn;
			}

			TlsInnerConn(TlsInnerConn&& other) :
				m_conn(other.m_conn)
			{
				other.m_conn = nullptr;
			}

			TlsInnerConn& operator=(TlsInnerConn&& rhs)
			{
				if (this != &rhs)
				{
					m_conn = rhs.m_conn;

					rhs.m_conn = nullptr;
				}

				return *this;
			}

			int Send(const void* buf, size_t len)
			{
				if (m_conn == nullptr)
				{
					throw RuntimeException("TlsInnerConn::Send - Connection pointer is null.");
				}
				if (len > 0 && buf == nullptr)
				{
					throw InvalidArgumentException("TlsInnerConn::Send - The given sending buffer is null.");
				}

				size_t sentBytes = m_conn->SendRaw(buf, len);
				return static_cast<int>(sentBytes);
			}

			int Recv(void* buf, size_t len)
			{
				if (m_conn == nullptr)
				{
					throw RuntimeException("TlsInnerConn::Send - Connection pointer is null.");
				}
				if (len > 0 && buf == nullptr)
				{
					throw InvalidArgumentException("TlsInnerConn::Send - The given sending buffer is null.");
				}

				size_t recvBytes = m_conn->RecvRaw(buf, len);
				return static_cast<int>(recvBytes);
			}

			int RecvTimeout(void* buf, size_t len, uint32_t t)
			{
				throw RuntimeException("TlsInnerConn::RecvTimeout - RecvTimeout is not supported.");
			}

		private:
			ConnectionBase* m_conn;
		};

		class TlsCommLayer : public SecureCommLayer, public mbedTLScpp::Tls<TlsInnerConn>
		{
		public:

			using _BaseCom = SecureCommLayer;
			using _BaseTls = mbedTLScpp::Tls<TlsInnerConn>;

		public:
			TlsCommLayer() = delete;

			TlsCommLayer(ConnectionBase& cnt,
				std::shared_ptr<const mbedTLScpp::TlsConfig> tlsConfig,
				std::shared_ptr<const mbedTLScpp::TlsSession> session) :
				_BaseTls::Tls(tlsConfig, session, mbedTLScpp::Internal::make_unique<TlsInnerConn>(&cnt))
			{}

			TlsCommLayer(const TlsCommLayer& other) = delete;

			TlsCommLayer(TlsCommLayer&& other) :
				_BaseTls::Tls(std::forward<_BaseTls>(other))
			{}

			virtual ~TlsCommLayer()
			{}

			TlsCommLayer& operator=(const TlsCommLayer& rhs) = delete;

			TlsCommLayer& operator=(TlsCommLayer&& rhs) noexcept
			{
				_BaseTls::operator=(std::forward<_BaseTls>(rhs));

				return *this;
			}

			using SecureCommLayer::SendRaw;
			virtual size_t SendRaw(const void* buf, const size_t size) override
			{
				return static_cast<size_t>(_BaseTls::SendData(buf, size));
			}

			using SecureCommLayer::RecvRaw;
			virtual size_t RecvRaw(void* buf, const size_t size) override
			{
				return static_cast<size_t>(_BaseTls::RecvData(buf, size));
			}

			virtual void SetConnectionPtr(ConnectionBase& cnt) override
			{
				_BaseTls::GetConnPtr()->SetConnPtr(&cnt);
			}

			virtual bool IsValid() const
			{
				return _BaseTls::IsNull();
			}

		};
	}
}
