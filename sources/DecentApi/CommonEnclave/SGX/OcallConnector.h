#pragma once

#include "../Net/EnclaveNetConnector.h"

#include "edl_decent_net.h"
#include "../../Common/Net/NetworkException.h"

namespace Decent
{
	namespace Net
	{
		/** \brief	An OCall connector that uses OCall function to establish connections. */
		class OcallConnector : public EnclaveNetConnector
		{
		public:
			OcallConnector() = delete;

			/**
			 * \brief	Constructor
			 *
			 * \exception	Decent::Net::Exception	Thrown when an exception error condition occurs. Error
			 * 										conditions are OCall failed, or the connection pointer
			 * 										received is null.
			 *
			 * \tparam	FuncT	Type of the OCall function, which must has the forms of "sgx_status_t
			 * 					FuncName(void* connection_ptr, ...)", where the "..." means any number of
			 * 					parameters, not the variable argument list.
			 * \tparam	Args 	Type of the arguments.
			 * \param	cntBuilder	The OCall function.
			 * \param	args	  	Variable arguments providing [in,out] The arguments.
			 */
			template<class FuncT, class... Args>
			OcallConnector(FuncT cntBuilder, Args&&... args) :
				EnclaveNetConnector()
			{
				if ((*cntBuilder)(&m_ptr, std::forward<Args>(args)...) != SGX_SUCCESS ||
					m_ptr == nullptr)
				{
					throw Decent::Net::Exception("Failed to establish connection via OCALL.");
				}
			}

			/** \brief	Destructor */
			virtual ~OcallConnector()
			{
				ocall_decent_net_cnet_close(m_ptr);
			}
		};
	}
}
