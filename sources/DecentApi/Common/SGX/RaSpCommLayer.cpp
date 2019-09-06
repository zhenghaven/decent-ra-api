#include "RaSpCommLayer.h"

#include <sgx_key_exchange.h>

#include "../Net/ConnectionBase.h"
#include "../Net/NetworkException.h"
#include "../MbedTls/SafeWrappers.h"

#include "../make_unique.h"
#include "RaTicket.h"
#include "RaProcessorSp.h"

using namespace Decent;
using namespace Decent::Net;
using namespace Decent::Sgx;

namespace
{
	static constexpr uint8_t gsk_resumeSucc = 1;
	static constexpr uint8_t gsk_resumeFail = 0;

	static constexpr uint8_t gsk_hasNewTicket = 1;
	static constexpr uint8_t gsk_noNewTicket = 0;
}

// SP side steps:
//     1. <--- Recv "Has Ticket" or "No Ticket"
//     If has ticket:
//         2. <--- Recv ticket
//         3. ---> Send "Resume Succ", and return
//         (If not succ, send "Resume Failed", and continue)
//     else:
//         2. <--- Recv RA MSG 0 Send
//         3. ---> Send RA MSG 0 Resp
//         4. <--- Recv RA MSG 1
//         5. ---> Send RA MSG 2
//         6. <--- Recv RA MSG 3
//         7. ---> Send RA MSG 4
//         If ticket sealed:
//             8. ---> Send "Has Ticket"
//             9. ---> Send Ticket
//         else:
//             8. ---> Send "No Ticket"
static std::unique_ptr<RaSession> DoHandShake(ConnectionBase& cnt, std::unique_ptr<RaProcessorSp> raProcessor,
	bool& isResumed, RaSpCommLayer::TicketSealer sealFunc, RaSpCommLayer::TicketSealer unsealFunc)
{
	if (!raProcessor)
	{
		throw Exception("Null pointer is given to the RA Processor SP DoHandShake.");
	}

	isResumed = false;

	uint8_t clientHasTicket = 0;
	cnt.RecvRawAll(&clientHasTicket, sizeof(clientHasTicket));

	if (clientHasTicket)
	{
		//try to resume the session
		
		std::vector<uint8_t> ticket = cnt.RecvContainer<std::vector<uint8_t> >();
		try
		{
			std::vector<uint8_t> sessionBin = unsealFunc(ticket);
			if (sessionBin.size() == RaSession::GetSize())
			{
				std::unique_ptr<RaSession> neSession = Tools::make_unique<RaSession>(sessionBin.cbegin(), sessionBin.cend());

				cnt.SendRawAll(&gsk_resumeSucc, sizeof(gsk_resumeSucc));

				isResumed = true;

				return std::move(neSession);
			}
		}
		catch (const std::exception&)
		{
			//Failed to unseal the ticket, go ahead and generate a new session.
		}

		cnt.SendRawAll(&gsk_resumeFail, sizeof(gsk_resumeFail));
	}
	
	raProcessor->Init();

	sgx_ra_msg0s_t msg0s;
	sgx_ra_msg0r_t msg0r;
	sgx_ra_msg1_t msg1;
	std::vector<uint8_t> msg2;
	std::vector<uint8_t> msg3;
	std::vector<uint8_t> msg4;

	cnt.RecvRawAll(&msg0s, sizeof(msg0s));

	raProcessor->ProcessMsg0(msg0s, msg0r);

	cnt.SendRawAll(&msg0r, sizeof(msg0r));
	cnt.RecvRawAll(&msg1, sizeof(msg1));

	raProcessor->ProcessMsg1(msg1, msg2);

	msg3 = cnt.SendAndRecvPack(msg2.data(), msg2.size());
	if (msg3.size() < sizeof(sgx_ra_msg3_t))
	{
		throw Exception("Decent::Sgx::RaProcessorSp DoHandShake Failed.");
	}
	raProcessor->ProcessMsg3(*reinterpret_cast<const sgx_ra_msg3_t*>(msg3.data()), msg3.size(), msg4, nullptr);

	cnt.SendContainer(msg4);

	std::unique_ptr<RaSession> neSession = Tools::make_unique<RaSession>();

	neSession->m_secretKey = raProcessor->GetSK();
	neSession->m_maskingKey = raProcessor->GetMK();
	neSession->m_iasReport = *raProcessor->ReleaseIasReport();

	//try to generate new ticket
	std::vector<uint8_t> neTicket;

	std::vector<uint8_t> sessionBin(neSession->GetSize());
	neSession->ToBinary(sessionBin.begin(), sessionBin.end());

	try
	{
		neTicket = sealFunc(sessionBin);
	}
	catch (const std::exception&)
	{
		//Failed to seal the data.
		cnt.SendRawAll(&gsk_noNewTicket, sizeof(gsk_noNewTicket));
		return std::move(neSession);
	}

	MbedTlsObj::ZeroizeContainer(sessionBin);

	cnt.SendRawAll(&gsk_hasNewTicket, sizeof(gsk_hasNewTicket));
	cnt.SendContainer(neTicket);

	return std::move(neSession);
}

RaSpCommLayer::RaSpCommLayer(ConnectionBase& cnt, std::unique_ptr<RaProcessorSp> raProcessor,
	bool& isResumed, TicketSealer sealFunc, TicketSealer unsealFunc) :
	RaSpCommLayer(cnt, DoHandShake(cnt, std::move(raProcessor), isResumed, sealFunc, unsealFunc))
{
}

RaSpCommLayer::RaSpCommLayer(RaSpCommLayer && other) :
	AesGcmCommLayer(std::forward<AesGcmCommLayer>(other)),
	m_session(std::move(other.m_session))
{
}

RaSpCommLayer::~RaSpCommLayer()
{
}

const sgx_ias_report_t & RaSpCommLayer::GetIasReport() const
{
	return m_session->m_iasReport;
}

const RaSession & RaSpCommLayer::GetSession() const
{
	return *m_session;
}

RaSpCommLayer::RaSpCommLayer(Net::ConnectionBase& cnt, std::unique_ptr<RaSession> session) :
	AesGcmCommLayer(session->m_secretKey, session->m_maskingKey, &cnt),
	m_session(std::move(session))
{
}
