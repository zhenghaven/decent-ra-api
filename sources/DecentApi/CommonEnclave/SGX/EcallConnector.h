#pragma once

#include "edl_decent_net.h"
#include "../../Common/Net/NetworkException.h"

namespace Decent
{
	namespace Net
	{
		struct EcallConnector
		{
			template<class Tp, class... Args>
			EcallConnector(Tp cntBuilder, Args&&... args) :
				m_ptr(nullptr)
			{
				if ((*cntBuilder)(&m_ptr, std::forward<Args>(args)...) != SGX_SUCCESS ||
					m_ptr == nullptr)
				{
					throw Decent::Net::Exception("Failed to establish connection via ECALL.");
				}
			}

			~EcallConnector()
			{
				ocall_decent_net_cnet_close(m_ptr);
			}
			void* m_ptr;
		};
	}
}
