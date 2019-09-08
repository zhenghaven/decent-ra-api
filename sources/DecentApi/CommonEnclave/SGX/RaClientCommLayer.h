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
		struct RaSession;

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
			 * \brief	Gets the original session. It can be saved and resumed later. original session
			 * 			contains ticket given by the SP, and the original symmetric key derived during
			 * 			standard RA process.
			 *
			 * \return	The original session.
			 */
			std::shared_ptr<const RaClientSession> GetOrigSession() const;

			/**
			 * \brief	Gets current session that is generated during the handshake, and its keys are the
			 * 			ones actually used in current session. If session is recovered from ticket, keys in
			 * 			current session is derived from keys in original session, otherwise, it's same as the
			 * 			ones in original session.
			 *
			 * \return	The current session.
			 */
			const RaSession& GetCurrSession() const;

		private:
			RaClientCommLayer(Net::ConnectionBase& connectionPtr, std::pair<std::shared_ptr<const RaClientSession>, std::unique_ptr<RaSession> > session);

			RaClientCommLayer(Net::ConnectionBase& connectionPtr, std::shared_ptr<const RaClientSession> origSession, std::unique_ptr<RaSession> currSession);

			/**
			 * \brief	m_origSession contains ticket given by the SP, and the original symmetric key derived
			 * 			during standard RA process. All these info should not be changed throughout the
			 * 			lifetime of the included ticket.
			 */
			std::shared_ptr<const RaClientSession> m_origSession;

			/**
			 * \brief	If session is recovered from ticket, keys in m_currSession is derived from keys in
			 * 			m_origSession
			 */
			std::unique_ptr<RaSession> m_currSession;
		};
	}
}
