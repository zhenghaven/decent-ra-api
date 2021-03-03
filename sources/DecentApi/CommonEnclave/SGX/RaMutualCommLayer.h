#pragma once

#include "RaClientCommLayer.h"
#include "../../Common/SGX/RaSpCommLayer.h"

namespace Decent
{
	namespace Sgx
	{
		

		class RaMutualCommLayer : public Net::AesGcmCommLayer
		{
		public:
			RaMutualCommLayer() = delete;
			RaMutualCommLayer(const RaMutualCommLayer&) = delete;

			/**
			 * \brief	Constructor for client side
			 *
			 * \param [in,out]	cnt	 	The connection pointer.
			 * \param 		  	clientRaProcessor	The SGX RA processor for client side.
			 * \param 		  	spRaProcessor	 	The SGX RA processor for SP side.
			 * \param 		  	savedSession	 	The saved session.
			 *
			 */
			RaMutualCommLayer(Net::ConnectionBase& cnt,
				std::unique_ptr<RaProcessorClient> clientRaProcessor, std::unique_ptr<RaProcessorSp> spRaProcessor,
				std::shared_ptr<const RaClientSession> savedSession);

			/**
			 * \brief	Constructor for server side
			 *
			 * \param [in,out]	cnt	 	The connection pointer.
			 * \param 		  	clientRaProcessor	The SGX RA processor for client side.
			 * \param 		  	spRaProcessor	 	The SGX RA processor for SP side.
			 * \param 		  	sealFunc		 	(Optional) The seal function used to generate the ticket.
			 * \param 		  	unsealFunc		 	(Optional) The unseal function used to parse the ticket.
			 *
			 */
			RaMutualCommLayer(Net::ConnectionBase& cnt,
				std::unique_ptr<RaProcessorClient> clientRaProcessor, std::unique_ptr<RaProcessorSp> spRaProcessor,
				RaSpCommLayer::TicketSealer sealFunc = RaSpCommLayer::TicketSealer(),
				RaSpCommLayer::TicketUnsealer unsealFunc = RaSpCommLayer::TicketUnsealer());

			RaMutualCommLayer(RaMutualCommLayer&& rhs);

			virtual ~RaMutualCommLayer();

			const sgx_ias_report_t& GetPeerIasReport() const;

			/**
			 * \brief	Gets the client session. It can be saved and resumed later.
			 *
			 * \return	The session.
			 */
			std::shared_ptr<const RaClientSession> GetClientSession() const;

		private:
			RaMutualCommLayer(Net::ConnectionBase& cnt, std::unique_ptr<RaSession> session);

			RaMutualCommLayer(Net::ConnectionBase& cnt, std::pair<std::shared_ptr<const RaClientSession>, std::unique_ptr<RaSession> > session);

			RaMutualCommLayer(Net::ConnectionBase& cnt, std::shared_ptr<const RaClientSession> origSession, std::unique_ptr<RaSession> currSession);

			std::shared_ptr<const RaClientSession> m_clientSession;

			std::unique_ptr<RaSession> m_spSession;
		};
	}
}
