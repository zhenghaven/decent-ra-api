#pragma once

#include <memory>

#include "../../Common/Net/AesGcmCommLayer.h"

typedef struct _sgx_ias_report_t sgx_ias_report_t;

namespace Decent
{
	namespace Sgx
	{
		class RaProcessorClient;
		struct RaClientSession;

		class RaClientCommLayer : public Decent::Net::AesGcmCommLayer
		{
		public:
			RaClientCommLayer() = delete;

			/**
			 * \brief	Constructor
			 *
			 * \param [in,out]	connectionPtr	The connection pointer.
			 * \param 		  	raProcessor  	The SGX RA processor for client side.
			 * \param 		  	savedSession 	The saved session used to resume a saved session. It can be
			 * 									nullptr if there is no saved session.
			 */
			RaClientCommLayer(Net::ConnectionBase& connectionPtr, std::unique_ptr<RaProcessorClient> raProcessor, std::shared_ptr<const RaClientSession> savedSession);

			RaClientCommLayer(const RaClientCommLayer& other) = delete;

			/**
			 * \brief	Move constructor
			 *
			 * \param [in,out]	rhs	The right hand side.
			 */
			RaClientCommLayer(RaClientCommLayer&& rhs);

			/** \brief	Destructor */
			virtual ~RaClientCommLayer();

			/**
			 * \brief	Gets IAS report generated from the RA process.
			 *
			 * \return	The ias report.
			 */
			const sgx_ias_report_t& GetIasReport() const;

			/**
			 * \brief	Gets the session. It can be saved and resumed later.
			 *
			 * \return	The session.
			 */
			std::shared_ptr<const RaClientSession> GetSession() const;

		private:
			RaClientCommLayer(Net::ConnectionBase& connectionPtr, std::shared_ptr<const RaClientSession> session);

			std::shared_ptr<const RaClientSession> m_session;

		};
	}
}
