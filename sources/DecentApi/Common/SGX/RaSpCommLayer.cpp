#include "RaSpCommLayer.h"

#include <sgx_key_exchange.h>

#include <mbedTLScpp/DefaultRbg.hpp>
#include <mbedTLScpp/Hash.hpp>
#include <mbedTLScpp/TlsPrf.hpp>
#include <mbedTLScpp/Hkdf.hpp>

#include "../Net/RpcWriter.h"
#include "../Net/RpcParser.h"
#include "../Net/ConnectionBase.h"
#include "../Net/NetworkException.h"

#include "../make_unique.h"
#include "../consttime_memequal.h"
#include "RaTicket.h"
#include "RaProcessorSp.h"

using namespace Decent::Net;
using namespace Decent::Sgx;
using namespace Decent::Tools;

namespace
{
	static constexpr uint8_t gsk_resumeSucc = 1;
	static constexpr uint8_t gsk_resumeFail = 0;

	static constexpr uint8_t gsk_hasNewTicket = 1;
	static constexpr uint8_t gsk_noNewTicket = 0;

	static constexpr char const gsk_keyDerLabel[] = "new_session_keys";
	static constexpr char const gsk_finishLabel[] = "finished";
	static constexpr size_t gsk_defPrfResSize = 12;
}

// Server steps:
//     1. <--- Recv client RPC, ("HasTicket" || Ticket || Nonce) OR ("NoTicket")
//     If no ticket:
//        FALL BACK to standard RA...
//     Else if failed to unseal ticket:
//        2. ---> Send "NotAccepted" RPC, ("NotAccepted")
//        FALL BACK to standard RA...
//     Else:
//        2. ---> Send "Accepted" RPC, ("Accepted" || Nonce)
//        3. Recv verification message, TLS-PRF(key=secret_key, gsk_finishLabel, Hash(Accepted_RPC))
//        4. Send verification message, TLS-PRF(key=secret_key, gsk_finishLabel, Hash(RPC_from_client))
//        5. Derive new set of keys: new_secret_key = HKDF(secret_key, label="new_session_keys", salt=(client_nonce || Nonce))
//                                   new_masking_key = HKDF(masking_key, label="new_session_keys", salt=(client_nonce || Nonce))
static std::unique_ptr<RaSession> ResumeSessionFromTicket(ConnectionBase& connection, RaSpCommLayer::TicketUnsealer unsealFunc)
{
	using namespace mbedTLScpp;

	std::array<uint64_t, 2> nonces;
	uint64_t& peerNonce = nonces[0]; //Client nonce is at first position
	uint64_t& selfNonce = nonces[1]; //Server nonce is at second position
	std::unique_ptr<RaSession> origSession;
	Hash<HashType::SHA256> selfMsgHash;
	Hash<HashType::SHA256> peerMsgHash;
	
	// 1. Recv client's RPC
	{
		RpcParser rpcResuTicket(connection.RecvContainer<std::vector<uint8_t> >());

		uint8_t hasTicket = rpcResuTicket.GetPrimitiveArg<uint8_t>();

		if (!hasTicket)
		{
			return nullptr; // Client doesn't have ticket.
		}

		try
		{
			peerMsgHash = Hasher<HashType::SHA256>().Calc(CtnFullR(rpcResuTicket.GetFullBinary()));

			auto ticketSpace = rpcResuTicket.GetBinaryArg();
			SecretVector<uint8_t> sessionBin = unsealFunc(std::vector<uint8_t>(ticketSpace.first, ticketSpace.second));
			peerNonce = rpcResuTicket.GetPrimitiveArg<uint64_t>();

			origSession = Decent::Tools::make_unique<RaSession>(sessionBin.cbegin(), sessionBin.cend());
		}
		catch (const std::exception&)
		{
			//Failed to unseal the ticket, inform the client, and go ahead and generate a new session.
			
			RpcWriter rpcFailedResu(RpcWriter::CalcSizePrim<uint8_t>(), 1);
			rpcFailedResu.AddPrimitiveArg<uint8_t>() = gsk_resumeFail;
			connection.SendRpc(rpcFailedResu);

			return nullptr;
		}
	}

	// 2. Generate a nonce:
	selfNonce = mbedTLScpp::DefaultRbg().GetRand<uint64_t>();

	// 3. Send resume result:
	{
		RpcWriter rpcSuccResu(RpcWriter::CalcSizePrim<uint8_t>() +
			RpcWriter::CalcSizePrim<uint64_t>(), 2, false);

		rpcSuccResu.AddPrimitiveArg<uint8_t>() = gsk_resumeSucc;
		rpcSuccResu.AddPrimitiveArg<uint64_t>() = selfNonce;
		connection.SendRpc(rpcSuccResu);

		selfMsgHash = Hasher<HashType::SHA256>().Calc(CtnFullR(rpcSuccResu.GetFullBinary()));
	}

	// 4. Recv client's verification message:
	{
		auto selfPrfRes = TlsPrf<TlsPrfType::SHA256, gsk_defPrfResSize>(
			CtnFullR(origSession->m_secretKey),
			gsk_finishLabel,
			CtnFullR(selfMsgHash)
		);

		std::vector<uint8_t> peerVrfyMsg = connection.RecvContainer<std::vector<uint8_t> >();

		if (peerVrfyMsg.size() != selfPrfRes.size() ||
			!consttime_memequal(peerVrfyMsg.data(), selfPrfRes.data(), selfPrfRes.size()))
		{
			// At this step, we don't fall back to RA process.
			throw Decent::Net::Exception("Failed to verify ticket resume message from client.");
		}
	}

	// 5. Send server's verification message:
	{
		auto peerPrfRes = TlsPrf<TlsPrfType::SHA256, gsk_defPrfResSize>(
			CtnFullR(origSession->m_secretKey),
			gsk_finishLabel,
			CtnFullR(peerMsgHash)
		);

		connection.SendContainer(peerPrfRes.Get());
	}

	// 6. Derive new keys to prevent replay attack:
	std::unique_ptr<RaSession> currSession = Decent::Tools::make_unique<RaSession>();
	{
		currSession->m_secretKey = Hkdf<HashType::SHA256, 128>(
			CtnFullR(origSession->m_secretKey),
			CtnFullR(gsk_keyDerLabel),
			CtnFullR(nonces)
		);
		currSession->m_maskingKey = Hkdf<HashType::SHA256, 128>(
			CtnFullR(origSession->m_maskingKey),
			CtnFullR(gsk_keyDerLabel),
			CtnFullR(nonces)
		);
	}

	origSession->m_secretKey = currSession->m_secretKey;
	origSession->m_maskingKey = currSession->m_maskingKey;
	return std::move(origSession);
}

static void GenerateAndSendTicket(ConnectionBase& cnt, const RaSession& session, RaSpCommLayer::TicketSealer sealFunc)
{
	std::vector<uint8_t> neTicket;

	try
	{
		using namespace mbedTLScpp;

		SecretVector<uint8_t> sessionBin(session.GetSize());
		session.ToBinary(sessionBin.begin(), sessionBin.end());
		neTicket = sealFunc(sessionBin);
	}
	catch (const std::exception&)
	{
		//Failed to seal the data, and tells client there is no ticket.
		RpcWriter rpcNoTicket(RpcWriter::CalcSizePrim<uint8_t>(),
			1);
		rpcNoTicket.AddPrimitiveArg<uint8_t>() = gsk_noNewTicket;
		cnt.SendRpc(rpcNoTicket);

		return;
	}

	RpcWriter rpcNewTicket(RpcWriter::CalcSizePrim<uint8_t>() +
		RpcWriter::CalcSizeBin(neTicket.size()), 2);
	rpcNewTicket.AddPrimitiveArg<uint8_t>() = gsk_hasNewTicket;
	rpcNewTicket.AddBinaryArg(neTicket.size()).Set(neTicket);
	cnt.SendRpc(rpcNewTicket);
}

// SP side steps:
//     GO TO resume session from ticket
//     If failed:
//         2. <--- Recv RA MSG 0 Send
//         3. ---> Send RA MSG 0 Resp
//         4. <--- Recv RA MSG 1
//         5. ---> Send RA MSG 2
//         6. <--- Recv RA MSG 3
//         7. ---> Send RA MSG 4
//         GO TO send ticket
static std::unique_ptr<RaSession> DoHandShake(ConnectionBase& cnt, std::unique_ptr<RaProcessorSp> raProcessor,
	bool& isResumed, RaSpCommLayer::TicketSealer sealFunc, RaSpCommLayer::TicketUnsealer unsealFunc)
{
	if (!raProcessor)
	{
		throw Exception("Null pointer is given to the RA Processor SP DoHandShake.");
	}

	isResumed = false;
	std::unique_ptr<RaSession> neSession = ResumeSessionFromTicket(cnt, unsealFunc);
	if (neSession)
	{
		isResumed = true;
		return std::move(neSession);
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

	neSession = Decent::Tools::make_unique<RaSession>();

	neSession->m_secretKey = raProcessor->GetSK();
	neSession->m_maskingKey = raProcessor->GetMK();
	neSession->m_iasReport = *raProcessor->ReleaseIasReport();

	GenerateAndSendTicket(cnt, *neSession, sealFunc);

	return std::move(neSession);
}

RaSpCommLayer::RaSpCommLayer(ConnectionBase& cnt, std::unique_ptr<RaProcessorSp> raProcessor,
	bool& isResumed, TicketSealer sealFunc, TicketUnsealer unsealFunc) :
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

RaSpCommLayer::RaSpCommLayer(Decent::Net::ConnectionBase& cnt, std::unique_ptr<RaSession> session) :
	AesGcmCommLayer(session->m_secretKey, session->m_maskingKey, &cnt),
	m_session(std::move(session))
{
}
