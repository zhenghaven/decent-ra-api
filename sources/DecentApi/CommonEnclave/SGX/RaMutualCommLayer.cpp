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
	static std::pair<std::shared_ptr<const RaClientSession>, ConnectionBase*> DoClientHandshake(ConnectionBase & cnt,
		std::unique_ptr<RaProcessorClient> clientRaProcessor, std::unique_ptr<RaProcessorSp> spRaProcessor,
		std::shared_ptr<const RaClientSession> savedSession)
	{
		RaClientCommLayer clientComm(cnt, std::move(clientRaProcessor), savedSession);

		std::shared_ptr<const RaClientSession> tmpNewSession = clientComm.GetSession();
		if (savedSession == tmpNewSession)
		{
			//Ticket is accepted by peer.
			return std::make_pair(savedSession, &cnt);
		}

		//New ticket is generated, so we need to verify the peer as well.
		
		bool isResumed = false;
		Sgx::RaSpCommLayer spComm(cnt, std::move(spRaProcessor), isResumed);

		std::shared_ptr<RaClientSession> neSession = std::make_shared<RaClientSession>(*tmpNewSession);

		neSession->m_session.m_iasReport = spComm.GetIasReport();

		return std::make_pair(neSession, &cnt);
	}

	static std::pair<std::unique_ptr<RaSession>, ConnectionBase*> DoSpHandshake(ConnectionBase & cnt,
		std::unique_ptr<RaProcessorClient> clientRaProcessor, std::unique_ptr<RaProcessorSp> spRaProcessor,
		RaSpCommLayer::TicketSealer sealFunc, RaSpCommLayer::TicketSealer unsealFunc)
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

		return std::make_pair(std::move(session), &cnt);
	}
}

RaMutualCommLayer::RaMutualCommLayer(ConnectionBase & cnt,
	std::unique_ptr<RaProcessorClient> clientRaProcessor, std::unique_ptr<RaProcessorSp> spRaProcessor,
	std::shared_ptr<const RaClientSession> savedSession) :
	RaMutualCommLayer(DoClientHandshake(cnt, std::move(clientRaProcessor), std::move(spRaProcessor), savedSession))
{
}

RaMutualCommLayer::RaMutualCommLayer(ConnectionBase & cnt,
	std::unique_ptr<RaProcessorClient> clientRaProcessor, std::unique_ptr<RaProcessorSp> spRaProcessor,
	RaSpCommLayer::TicketSealer sealFunc, RaSpCommLayer::TicketSealer unsealFunc) :
	RaMutualCommLayer(DoSpHandshake(cnt, std::move(clientRaProcessor), std::move(spRaProcessor), sealFunc, unsealFunc))
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

RaMutualCommLayer::RaMutualCommLayer(std::pair<std::unique_ptr<RaSession>, Net::ConnectionBase*> hsResult) :
	AesGcmCommLayer(hsResult.first->m_secretKey, hsResult.second),
	m_clientSession(),
	m_spSession(std::move(hsResult.first))
{
}

RaMutualCommLayer::RaMutualCommLayer(std::pair<std::shared_ptr<const RaClientSession>, Net::ConnectionBase*> hsResult) :
	AesGcmCommLayer(hsResult.first->m_session.m_secretKey, hsResult.second),
	m_clientSession(hsResult.first),
	m_spSession()
{
}
