#pragma once

#include <memory>
#include <string>
#include <functional>

#include "../Net/AesGcmCommLayer.h"

typedef struct _sgx_ias_report_t sgx_ias_report_t;

namespace Decent
{
	namespace Ra
	{
		class States;
	}

	namespace Sgx
	{
		class RaProcessorSp;
		struct RaSession;

		class RaSpCommLayer : public Decent::Net::AesGcmCommLayer
		{
		public: //static members:
			typedef std::function<std::vector<uint8_t>(const std::vector<uint8_t>&)> TicketSealer;

		public:
			RaSpCommLayer() = delete;
			RaSpCommLayer(const RaSpCommLayer& other) = delete;

			/**
			 * \brief	Constructor
			 *
			 * \param [in,out]	cnt		   	Connection.
			 * \param 		  	raProcessor	The SGX RA processor for SP side.
			 * \param [out]	  	isResumed  	True if is resumed from client's ticket, false if not.
			 * \param 		  	sealFunc   	(Optional) The seal function. Function used to seal the session
			 * 								ticket. If nothing is given or an empty function is given, no
			 * 								session ticket will be generated. All exception raised in this
			 * 								function will be caught, and treated as failed (no ticket will be
			 * 								generated).
			 * \param 		  	unsealFunc 	(Optional) The unseal function. Function used to unseal the
			 * 								session ticket. If nothing is given or an empty function is given,
			 * 								session will not be resumed from the ticket. All exception raised
			 * 								in this function will be caught, and treated as failed (no
			 * 								session will be resumed).
			 */
			RaSpCommLayer(Net::ConnectionBase& cnt, std::unique_ptr<RaProcessorSp> raProcessor,
				bool& isResumed, TicketSealer sealFunc = TicketSealer(), TicketSealer unsealFunc = TicketSealer());

			/**
			 * \brief	Move constructor
			 *
			 * \param [in,out]	rhs	The right hand side.
			 */
			RaSpCommLayer(RaSpCommLayer&& rhs);

			/** \brief	Destructor */
			virtual ~RaSpCommLayer();

			/**
			 * \brief	Gets IAS report
			 *
			 * \return	The IAS report.
			 */
			const sgx_ias_report_t& GetIasReport() const;

			/**
			 * \brief	Gets the session
			 *
			 * \return	The session.
			 */
			const RaSession& GetSession() const;

		private:
			RaSpCommLayer(std::pair<std::unique_ptr<RaSession>, Net::ConnectionBase*> hsResult);

			std::unique_ptr<RaSession> m_session;
		};
	}
}
