#pragma once

#include "ConnectionBase.h"

#include <memory>

#include "ConnectionPool.h"

namespace Decent
{
	namespace Net
	{
		template<typename MapKeyType>
		class CntPoolConnection : public ConnectionBase
		{
		public:
			CntPoolConnection() = delete;

			CntPoolConnection(const MapKeyType& addr, std::unique_ptr<ConnectionBase>&& cntPtr, std::shared_ptr<ConnectionPool<MapKeyType> > cntPool) :
				m_addr(addr), 
				m_cntPtr(std::forward<std::unique_ptr<ConnectionBase> >(cntPtr)),
				m_cntPool(cntPool)
			{}

			virtual ~CntPoolConnection()
			{
				m_cntPool->Put(m_addr, std::move(m_cntPtr));
			}

			virtual size_t SendRaw(const void* const dataPtr, const size_t size) override
			{
				return m_cntPtr->SendRaw(dataPtr, size);
			}

			virtual void SendRawAll(const void* const dataPtr, const size_t size) override
			{
				return m_cntPtr->SendRawAll(dataPtr, size);
			}

			virtual void SendPack(const void* const dataPtr, const size_t size) override
			{
				return m_cntPtr->SendPack(dataPtr, size);
			}


			virtual size_t RecvRaw(void* const bufPtr, const size_t size) override
			{
				return m_cntPtr->RecvRaw(bufPtr, size);
			}

			virtual void RecvRawAll(void* const bufPtr, const size_t size) override
			{
				return m_cntPtr->RecvRawAll(bufPtr, size);
			}

			virtual size_t RecvPack(uint8_t*& dest) override
			{
				return m_cntPtr->RecvPack(dest);
			}


			virtual std::vector<uint8_t> SendAndRecvPack(const void* const inData, const size_t inDataLen) override
			{
				return m_cntPtr->SendAndRecvPack(inData, inDataLen);
			}


			virtual void Terminate() noexcept override
			{
				return m_cntPtr->Terminate();
			}

		private:
			MapKeyType m_addr;
			std::unique_ptr<ConnectionBase> m_cntPtr;
			std::shared_ptr<ConnectionPool<MapKeyType> > m_cntPool;
		};
	}
}
