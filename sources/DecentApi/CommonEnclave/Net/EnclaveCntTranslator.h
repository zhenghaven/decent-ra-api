#pragma once

#include "../../Common/Net/ConnectionBase.h"

namespace Decent
{
	namespace Net
	{
		class EnclaveCntTranslator : public ConnectionBase
		{
		public:
			EnclaveCntTranslator() = delete;

			EnclaveCntTranslator(const EnclaveCntTranslator&) = delete;

			EnclaveCntTranslator(void* cntPtr) :
				m_cntPtr(cntPtr)
			{}

			EnclaveCntTranslator(EnclaveCntTranslator&& other) :
				m_cntPtr(other.m_cntPtr)
			{
				other.m_cntPtr = nullptr;
			}

			virtual ~EnclaveCntTranslator() {}

			/**
			* \brief	Move assignment operator
			*
			* \param [in,out]	rhs	The right hand side.
			*
			* \return	A reference to this object.
			*/
			EnclaveCntTranslator& operator=(EnclaveCntTranslator&& rhs)
			{
				if (this != &rhs)
				{
					void* tmp = this->m_cntPtr;
					this->m_cntPtr = rhs.m_cntPtr;
					rhs.m_cntPtr = tmp;
				}
				return *this;
			}

			using ConnectionBase::SendRaw;

			virtual size_t SendRaw(const void* const dataPtr, const size_t size);

			using ConnectionBase::SendPack;

			virtual void SendPack(const void* const dataPtr, const size_t size);

			using ConnectionBase::ReceiveRaw;

			virtual size_t ReceiveRaw(void* const bufPtr, const size_t size);

			using ConnectionBase::ReceivePack;

			virtual void ReceivePack(std::string& outMsg);

			virtual void ReceivePack(std::vector<uint8_t>& outMsg);

			using ConnectionBase::SendAndReceivePack;

			virtual void SendAndReceivePack(const void* const inData, const size_t inDataLen, std::string& outMsg);

			void* GetPointer() const { return m_cntPtr; }

		protected:
			void* m_cntPtr;
		};
	}
}
