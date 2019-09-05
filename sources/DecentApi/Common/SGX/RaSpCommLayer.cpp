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

static std::pair<std::unique_ptr<RaSession>, ConnectionBase*> DoHandShake(ConnectionBase& cnt, std::unique_ptr<RaProcessorSp> raProcessor,
	bool& isResumed, RaSpCommLayer::TicketSealer sealFunc, RaSpCommLayer::TicketSealer unsealFunc)
{
	if (!raProcessor)
	{
		throw Exception("Null pointer is given to the RA Processor SP DoHandShake.");
	}

	std::unique_ptr<RaSession> neSession = Tools::make_unique<RaSession>();

	uint8_t clientHasTicket = 0;
	cnt.RecvRawAll(&clientHasTicket, sizeof(clientHasTicket));

	if (clientHasTicket)
	{
		//try to resume the session
		
		std::vector<uint8_t> ticket = cnt.RecvContainer<std::vector<uint8_t> >();
		try
		{
			std::vector<uint8_t> sessionBin = unsealFunc(ticket);
			if (sessionBin.size() == sizeof(*neSession))
			{
				memcpy(neSession.get(), sessionBin.data(), sessionBin.size());

				cnt.SendRawAll(&gsk_resumeSucc, sizeof(gsk_resumeSucc));

				isResumed = true;

				return std::make_pair(std::move(neSession), &cnt);
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
		return std::make_pair(std::move(neSession), &cnt);
	}

	MbedTlsObj::ZeroizeContainer(sessionBin);

	cnt.SendRawAll(&gsk_hasNewTicket, sizeof(gsk_hasNewTicket));
	cnt.SendContainer(neTicket);

	return std::make_pair(std::move(neSession), &cnt);
}

RaSpCommLayer::RaSpCommLayer(ConnectionBase& cnt, std::unique_ptr<RaProcessorSp> raProcessor,
	bool& isResumed, TicketSealer sealFunc, TicketSealer unsealFunc) :
	RaSpCommLayer(DoHandShake(cnt, std::move(raProcessor), isResumed, sealFunc, unsealFunc))
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

RaSpCommLayer::RaSpCommLayer(std::pair<std::unique_ptr<RaSession>, ConnectionBase*> hsResult) :
	AesGcmCommLayer(hsResult.first->m_secretKey, hsResult.second),
	m_session(std::move(hsResult.first))
{
}
