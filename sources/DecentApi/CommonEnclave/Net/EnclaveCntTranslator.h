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

			using ConnectionBase::RecvRaw;

			virtual size_t RecvRaw(void* const bufPtr, const size_t size);

			using ConnectionBase::RecvPack;

			using ConnectionBase::SendAndRecvPack;

			virtual void SendAndRecvPack(const void* const inData, const size_t inDataLen, std::string& outMsg);

			void* GetPointer() const { return m_cntPtr; }

			virtual void Terminate() noexcept override;

		protected:
			void* m_cntPtr;
		};
	}
}
