#include "RaMutualCommLayer.h"

#include "../../Common/make_unique.h"
#include "../../Common/Net/ConnectionBase.h"
#include "../../Common/SGX/RaTicket.h"
#include "../../Common/SGX/RaProcessorSp.h"

#include "RaProcessorClient.h"

using namespace Decent;
using namespace Decent::Net;
using namespace Decent::Tools;
using namespace Decent::Sgx;

namespace
{
	// Client side steps:
	//     1. Follow RA Client steps
	//     If session is recovered from saved one:
	//         2. Return session from RA Client steps
	//     else:
	//         2. Follow RA SP steps
	//         3. Save peer's identity from SP steps
	//         4. Return session from RA Client steps
	static std::pair<std::shared_ptr<const RaClientSession>, std::unique_ptr<RaSession> >
		DoClientHandshake(ConnectionBase & cnt, std::unique_ptr<RaProcessorClient> clientRaProcessor, std::unique_ptr<RaProcessorSp> spRaProcessor,
		std::shared_ptr<const RaClientSession> savedSession)
	{
		RaClientCommLayer clientComm(cnt, std::move(clientRaProcessor), savedSession);

		std::shared_ptr<const RaClientSession> tmpNewSession = clientComm.GetOrigSession();
		if (savedSession && savedSession == tmpNewSession)
		{
			//Ticket is accepted by peer; the handshake is finished
			return std::make_pair(tmpNewSession, Tools::make_unique<RaSession>(clientComm.GetCurrSession()));
		}

		//New ticket is generated, so we need to verify the peer as well.
		
		bool isResumed = false;
		Sgx::RaSpCommLayer spComm(cnt, std::move(spRaProcessor), isResumed);

		std::shared_ptr<RaClientSession> neSession = std::make_shared<RaClientSession>(*tmpNewSession);

		neSession->m_session.m_iasReport = spComm.GetIasReport();

		return std::make_pair(neSession, Tools::make_unique<RaSession>(clientComm.GetCurrSession()));
	}

	// Server side steps:
	//     1. Follow RA SP steps
	//     2. Keep session
	//     If it was NOT resumed from ticket:
	//         3. Follow RA client steps
	//     3.(or 4.) Return session from RA SP steps
	static std::unique_ptr<RaSession> DoSpHandshake(ConnectionBase & cnt,
		std::unique_ptr<RaProcessorClient> clientRaProcessor, std::unique_ptr<RaProcessorSp> spRaProcessor,
		RaSpCommLayer::TicketSealer sealFunc, RaSpCommLayer::TicketUnsealer unsealFunc)
	{
		bool isResumed = false;
		Sgx::RaSpCommLayer spComm(cnt, std::move(spRaProcessor), isResumed, sealFunc, unsealFunc);

		std::unique_ptr<RaSession> session = Tools::make_unique<RaSession>(spComm.GetSession());

		if (!isResumed)
		{
			//New session need to be constructed. Peer needs to verify us.

			RaClientCommLayer clientComm(cnt, std::move(clientRaProcessor), nullptr);
		}

		//Otherwise, session is resumed from a ticket.

		return std::move(session);
	}
}

RaMutualCommLayer::RaMutualCommLayer(ConnectionBase & cnt,
	std::unique_ptr<RaProcessorClient> clientRaProcessor, std::unique_ptr<RaProcessorSp> spRaProcessor,
	std::shared_ptr<const RaClientSession> savedSession) :
	RaMutualCommLayer(cnt, DoClientHandshake(cnt, std::move(clientRaProcessor), std::move(spRaProcessor), savedSession))
{
}

RaMutualCommLayer::RaMutualCommLayer(ConnectionBase & cnt,
	std::unique_ptr<RaProcessorClient> clientRaProcessor, std::unique_ptr<RaProcessorSp> spRaProcessor,
	RaSpCommLayer::TicketSealer sealFunc, RaSpCommLayer::TicketUnsealer unsealFunc) :
	RaMutualCommLayer(cnt, DoSpHandshake(cnt, std::move(clientRaProcessor), std::move(spRaProcessor), sealFunc, unsealFunc))
{
}

RaMutualCommLayer::RaMutualCommLayer(RaMutualCommLayer && rhs) :
	AesGcmCommLayer(std::forward<AesGcmCommLayer>(rhs)),
	m_clientSession(std::forward<decltype(m_clientSession)>(rhs.m_clientSession)),
	m_spSession(std::forward<decltype(m_spSession)>(rhs.m_spSession))
{
}

RaMutualCommLayer::~RaMutualCommLayer()
{
}

const sgx_ias_report_t & RaMutualCommLayer::GetPeerIasReport() const
{
	if (m_clientSession)
	{
		return m_clientSession->m_session.m_iasReport;
	}
	else
	{
		return m_spSession->m_iasReport;
	}
}

std::shared_ptr<const RaClientSession> RaMutualCommLayer::GetClientSession() const
{
	return m_clientSession;
}

RaMutualCommLayer::RaMutualCommLayer(Net::ConnectionBase& cnt, std::unique_ptr<RaSession> session) :
	AesGcmCommLayer(session->m_secretKey, session->m_maskingKey, &cnt),
	m_clientSession(),
	m_spSession(std::move(session))
{
}

RaMutualCommLayer::RaMutualCommLayer(Net::ConnectionBase& cnt, std::pair<std::shared_ptr<const RaClientSession>, std::unique_ptr<RaSession> > session) :
	RaMutualCommLayer(cnt, session.first, std::move(session.second))
{
}

RaMutualCommLayer::RaMutualCommLayer(Net::ConnectionBase& cnt, std::shared_ptr<const RaClientSession> origSession, std::unique_ptr<RaSession> currSession) :
	AesGcmCommLayer(currSession->m_secretKey, currSession->m_maskingKey, &cnt),
	m_clientSession(origSession),
	m_spSession()
{
}
