#include "RaClientCommLayer.h"

#include "../Net/EnclaveCntTranslator.h"
#include "../../Common/Net/NetworkException.h"
#include "../../Common/SGX/RaTicket.h"

#include "RaProcessorClient.h"
#include "edl_decent_sgx_client.h"

using namespace Decent::Sgx;
using namespace Decent::Net;

namespace
{
	static constexpr uint8_t gsk_hasTicket = 1;
	static constexpr uint8_t gsk_noTicket = 0;
}

// Client side steps:
//     If there is saved ticket:
//         1. ---> Send "Has ticket"
//         2. ---> Send ticket via plain network channel
//         3. <--- Recv resume succ or not result
//     else:
//         1. ---> Send "No Ticket"
//         2. ---> Send RA MSG 0 Send
//         3. <--- Recv RA MSG 0 Resp
//         4. ---> Send RA MSG 1
//         5. <--- Recv RA MSG 2
//         6. ---> Send RA MSG 3
//         7. <--- Recv RA MSG 4
//         8. <--- Recv "Has Ticket" or "No Ticket"
//         If has ticket:
//             9. <--- Recv ticket
static std::shared_ptr<const RaClientSession> DoHandShake(ConnectionBase& connection, std::unique_ptr<RaProcessorClient> raProcessor, std::shared_ptr<const RaClientSession> savedSession)
{
	if (!raProcessor)
	{
		throw Exception("Null pointer is given to the Decent::Sgx::RaProcessorClient DoHandShake.");
	}

	if (savedSession && savedSession->m_ticket.size() > 0)
	{
		//There is saved session, try to resume it first.
		connection.SendRawAll(&gsk_hasTicket, sizeof(gsk_hasTicket));
		
		connection.SendContainer(savedSession->m_ticket);

		uint8_t resumeSucc = 0;

		connection.RecvRawAll(&resumeSucc, sizeof(resumeSucc));

		if (resumeSucc)
		{
			//Successfully resume the session. Return the resumed session.
			return savedSession;
		}

		//Failed to resume the session.
		//Go ahead and do the RA.
	}
	else
	{
		//There is no saved session, tell the SP now.
		connection.SendRawAll(&gsk_noTicket, sizeof(gsk_noTicket));
	}

	//Perform SGX RA...
	
	sgx_ra_msg0s_t msg0s;
	sgx_ra_msg0r_t msg0r;
	sgx_ra_msg1_t msg1;
	std::vector<uint8_t> msg2;
	std::vector<uint8_t> msg3;
	std::vector<uint8_t> msg4;

	raProcessor->GetMsg0s(msg0s);

	connection.SendRawAll(&msg0s, sizeof(msg0s));
	connection.RecvRawAll(&msg0r, sizeof(msg0r));

	raProcessor->ProcessMsg0r(msg0r, msg1);

	connection.SendRawAll(&msg1, sizeof(msg1));
	msg2 = connection.RecvContainer<std::vector<uint8_t> >();

	if (msg2.size() < sizeof(sgx_ra_msg2_t))
	{
		throw Exception("Decent::Sgx::RaProcessorClient DoHandShake Failed.");
	}

	raProcessor->ProcessMsg2(*reinterpret_cast<const sgx_ra_msg2_t*>(msg2.data()), msg2.size(), msg3);

	connection.SendContainer(msg3);
	msg4 = connection.RecvContainer<std::vector<uint8_t> >();

	raProcessor->ProcessMsg4(msg4);

	std::shared_ptr<RaClientSession> neSession = std::make_shared<RaClientSession>();

	uint8_t hasNewTicket = 0;
	connection.RecvRawAll(&hasNewTicket, sizeof(hasNewTicket));
	if (hasNewTicket)
	{
		neSession->m_ticket = connection.RecvContainer<std::vector<uint8_t> >();
	}

	neSession->m_session.m_secretKey = raProcessor->GetSK();
	neSession->m_session.m_maskingKey = raProcessor->GetMK();
	neSession->m_session.m_iasReport = *raProcessor->ReleaseIasReport();

	return neSession;
}

RaClientCommLayer::RaClientCommLayer(ConnectionBase& connection, std::unique_ptr<RaProcessorClient> raProcessor, std::shared_ptr<const RaClientSession> savedSession) :
	RaClientCommLayer(connection, DoHandShake(connection, std::move(raProcessor), savedSession))
{
}

RaClientCommLayer::RaClientCommLayer(RaClientCommLayer && rhs) :
	AesGcmCommLayer(std::forward<AesGcmCommLayer>(rhs)),
	m_session(std::move(rhs.m_session))
{
}

RaClientCommLayer::~RaClientCommLayer()
{
}

const sgx_ias_report_t & RaClientCommLayer::GetIasReport() const
{
	return m_session->m_session.m_iasReport;
}

std::shared_ptr<const RaClientSession> RaClientCommLayer::GetSession() const
{
	return m_session;
}

RaClientCommLayer::RaClientCommLayer(ConnectionBase& connectionPtr, std::shared_ptr<const RaClientSession> session) :
	AesGcmCommLayer(session->m_session.m_secretKey, session->m_session.m_maskingKey, &connectionPtr),
	m_session(session)
{
}
