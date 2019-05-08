#pragma once

#include "../../Common/Net/ConnectionBase.h"

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
				m_cntPool->AsycPut(m_addr, std::move(m_cntPtr));
			}

			virtual size_t SendRaw(const void* const dataPtr, const size_t size)
			{
				return m_cntPtr->SendRaw(dataPtr, size);
			}

			virtual void SendRawGuarantee(const void* const dataPtr, const size_t size)
			{
				m_cntPtr->SendRawGuarantee(dataPtr, size);
			}

			virtual void SendPack(const void* const dataPtr, const size_t size)
			{
				m_cntPtr->SendPack(dataPtr, size);
			}

			virtual void SendPack(const Tools::JsonValue& json)
			{
				m_cntPtr->SendPack(json);
			}


			virtual size_t ReceiveRaw(void* const bufPtr, const size_t size)
			{
				return m_cntPtr->ReceiveRaw(bufPtr, size);
			}

			virtual void ReceiveRawGuarantee(void* const bufPtr, const size_t size)
			{
				m_cntPtr->ReceiveRawGuarantee(bufPtr, size);
			}

			virtual size_t ReceivePack(char*& dest)
			{
				return m_cntPtr->ReceivePack(dest);
			}

			virtual void ReceivePack(Tools::JsonDoc& msg)
			{
				m_cntPtr->ReceivePack(msg);
			}

			virtual void ReceivePack(std::string& outMsg)
			{
				m_cntPtr->ReceivePack(outMsg);
			}

			virtual void ReceivePack(std::vector<uint8_t>& outMsg)
			{
				m_cntPtr->ReceivePack(outMsg);
			}


			virtual void SendAndReceivePack(const void* const inData, const size_t inDataLen, std::string& outMsg)
			{
				m_cntPtr->SendAndReceivePack(inData, inDataLen, outMsg);
			}


			virtual void Terminate() noexcept
			{
				m_cntPtr->Terminate();
			}

		private:
			MapKeyType m_addr;
			std::unique_ptr<ConnectionBase> m_cntPtr;
			std::shared_ptr<ConnectionPool<MapKeyType> > m_cntPool;
		};
	}
}
