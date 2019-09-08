#include "RaClientCommLayer.h"

#include "../../Common/make_unique.h"
#include "../../Common/consttime_memequal.h"

#include "../../Common/GeneralKeyTypes.h"

#include "../Net/EnclaveCntTranslator.h"
#include "../../Common/Net/RpcWriter.h"
#include "../../Common/Net/RpcParser.h"
#include "../../Common/Net/NetworkException.h"

#include "../../Common/MbedTls/Kdf.h"
#include "../../Common/MbedTls/Drbg.h"
#include "../../Common/MbedTls/Hasher.h"

#include "../../Common/Tools/Crypto.h"

#include "../../Common/SGX/RaTicket.h"

#include "RaProcessorClient.h"
#include "edl_decent_sgx_client.h"

using namespace Decent::Sgx;
using namespace Decent::Net;

namespace
{
	static constexpr uint8_t gsk_hasTicket = 1;
	static constexpr uint8_t gsk_noTicket = 0;

	static constexpr char const gsk_keyDerLabel[] = "new_session_keys";
}

static std::unique_ptr<RaSession> ResumeSessionFromTicket(ConnectionBase& connection, std::shared_ptr<const RaClientSession> savedSession)
{
	// If there is no saved ticket:
	if (!savedSession || savedSession->m_ticket.size() == 0)
	{
		RpcWriter rpcResuTicket(RpcWriter::CalcSizePrim<uint8_t>(),
			1);
		rpcResuTicket.AddPrimitiveArg<uint8_t>() = gsk_noTicket;
		connection.SendRpc(rpcResuTicket);

		return nullptr;
	}

	// Otherwise, try to resume session:

	std::array<uint64_t, 2> nonces;
	uint64_t& selfNonce = nonces[0]; //Client nonce is at first position
	uint64_t& peerNonce = nonces[1]; //Server nonce is at second position
	uint8_t ticketRes = false;
	Decent::General256Hash selfMsgHash;
	Decent::General256Hash peerMsgHash;

	// 1. Generate a nonce:
	Decent::MbedTlsObj::Drbg drbg;
	drbg.RandStruct(selfNonce);

	// 2. Construct and send RPC to peer:
	{
		RpcWriter rpcResuTicket(RpcWriter::CalcSizePrim<uint8_t>() +
			RpcWriter::CalcSizeBin(savedSession->m_ticket.size()) +
			RpcWriter::CalcSizePrim<uint64_t>(),
			3, false);

		rpcResuTicket.AddPrimitiveArg<uint8_t>() = gsk_hasTicket;
		rpcResuTicket.AddBinaryArg(savedSession->m_ticket.size()).Set(savedSession->m_ticket);
		rpcResuTicket.AddPrimitiveArg<uint64_t>() = selfNonce;

		connection.SendRpc(rpcResuTicket);

		// Generate hash to verify in later step:
		using namespace Decent::MbedTlsObj;
		Hasher::ArrayBatchedCalc<HashType::SHA256>(selfMsgHash, rpcResuTicket.GetFullBinary());
	}

	// 3. Recv RPC from peer:
	{
		RpcParser rpcResuRes(connection.RecvContainer<std::vector<uint8_t> >());

		// Generate hash to give to peer for verification:
		using namespace Decent::MbedTlsObj;
		Hasher::ArrayBatchedCalc<HashType::SHA256>(peerMsgHash, rpcResuRes.GetFullBinary());

		ticketRes = rpcResuRes.GetPrimitiveArg<uint8_t>();

		peerNonce = ticketRes ? rpcResuRes.GetPrimitiveArg<uint64_t>() : 0;
	}

	// ==> If ticket is NOT accepted by the peer:
	if (!ticketRes)
	{
		return nullptr;
	}

	// ==> Otherwise, the ticket is accepted by the peer:
	// 4. Generate and send verification message:
	{
		Decent::MbedTlsObj::SecretKeyWrap<GENERAL_128BIT_16BYTE_SIZE + sizeof(uint64_t)> selfAdd;
		std::copy(savedSession->m_session.m_maskingKey.m_key.begin(), savedSession->m_session.m_maskingKey.m_key.end(), selfAdd.m_key.begin());
		std::memcpy(selfAdd.m_key.data() + GENERAL_128BIT_16BYTE_SIZE, &peerNonce, sizeof(uint64_t));

		std::vector<uint8_t> selfVrfyMsg = Decent::Tools::QuickAesGcmPack(savedSession->m_session.m_secretKey.m_key,
			std::array<uint8_t, 0>(), std::array<uint8_t, 0>(), peerMsgHash, selfAdd.m_key, nullptr, GENERAL_128BIT_16BYTE_SIZE * GENERAL_BITS_PER_BYTE);

		connection.SendContainer(selfVrfyMsg);
	}

	// 5. Recv verification message from peer:
	{
		Decent::MbedTlsObj::SecretKeyWrap<GENERAL_128BIT_16BYTE_SIZE + sizeof(uint64_t)> peerAdd;
		std::copy(savedSession->m_session.m_maskingKey.m_key.begin(), savedSession->m_session.m_maskingKey.m_key.end(), peerAdd.m_key.begin());
		std::memcpy(peerAdd.m_key.data() + GENERAL_128BIT_16BYTE_SIZE, &selfNonce, sizeof(uint64_t));

		std::vector<uint8_t> peerVrfyMsgEnc = connection.RecvContainer<std::vector<uint8_t> >();
		std::vector<uint8_t> meta;
		std::vector<uint8_t> peerVrfyMsg;
		Decent::Tools::QuickAesGcmUnpack(savedSession->m_session.m_secretKey.m_key, peerVrfyMsgEnc, peerAdd.m_key,
			meta, peerVrfyMsg, nullptr, GENERAL_128BIT_16BYTE_SIZE * GENERAL_BITS_PER_BYTE);

		if (peerVrfyMsg.size() != selfMsgHash.size() ||
			!consttime_memequal(peerVrfyMsg.data(), selfMsgHash.data(), selfMsgHash.size()))
		{
			// At this step, we don't fall back to RA process.
			throw Decent::Net::Exception("Failed to verify ticket resume message from server.");
		}
	}

	// 6. Derive new keys to prevent replay attack:
	std::unique_ptr<RaSession> currSession = Decent::Tools::make_unique<RaSession>();
	{
		using namespace Decent::MbedTlsObj;
		HKDF<HashType::SHA256>(savedSession->m_session.m_secretKey.m_key, gsk_keyDerLabel, nonces, currSession->m_secretKey.m_key);
		HKDF<HashType::SHA256>(savedSession->m_session.m_maskingKey.m_key, gsk_keyDerLabel, nonces, currSession->m_maskingKey.m_key);
	}

	//Successfully resume the session. Return the resumed session.
	return std::move(currSession);
}

static std::vector<uint8_t> GetTicketFromServer(ConnectionBase& connection)
{
	RpcParser rpcTicket(connection.RecvContainer<std::vector<uint8_t> >());
	
	uint8_t hasNewTicket = rpcTicket.GetPrimitiveArg<uint8_t>();
	if (hasNewTicket)
	{
		auto ticketSpace = rpcTicket.GetBinaryArg();
		return std::vector<uint8_t>(ticketSpace.first, ticketSpace.second);
	}

	return std::vector<uint8_t>();
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
static std::pair<std::shared_ptr<const RaClientSession>, std::unique_ptr<RaSession> > DoHandShake(ConnectionBase& connection, std::unique_ptr<RaProcessorClient> raProcessor, std::shared_ptr<const RaClientSession> savedSession)
{
	if (!raProcessor)
	{
		throw Exception("Null pointer is given to the Decent::Sgx::RaProcessorClient DoHandShake.");
	}

	std::unique_ptr<RaSession> currSession = ResumeSessionFromTicket(connection, savedSession);

	if (currSession)
	{
		// Successfully resumed the session
		return std::make_pair(savedSession, std::move(currSession));
	}
	// Otherwise, failed to resume the session, fallback to normal RA.

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

	std::shared_ptr<RaClientSession> origSession = std::make_shared<RaClientSession>();

	//Get ticket from server.
	origSession->m_ticket = GetTicketFromServer(connection);

	origSession->m_session.m_secretKey = raProcessor->GetSK();
	origSession->m_session.m_maskingKey = raProcessor->GetMK();
	origSession->m_session.m_iasReport = *raProcessor->ReleaseIasReport();

	currSession = Decent::Tools::make_unique<RaSession>();
	currSession->m_secretKey = origSession->m_session.m_secretKey;
	currSession->m_maskingKey = origSession->m_session.m_maskingKey;

	return std::make_pair(origSession, std::move(currSession));
}

RaClientCommLayer::RaClientCommLayer(ConnectionBase& connection, std::unique_ptr<RaProcessorClient> raProcessor, std::shared_ptr<const RaClientSession> savedSession) :
	RaClientCommLayer(connection, DoHandShake(connection, std::move(raProcessor), savedSession))
{
}

RaClientCommLayer::RaClientCommLayer(RaClientCommLayer && rhs) :
	AesGcmCommLayer(std::forward<AesGcmCommLayer>(rhs)),
	m_origSession(std::move(rhs.m_origSession)),
	m_currSession(std::move(rhs.m_currSession))
{
}

RaClientCommLayer::~RaClientCommLayer()
{
}

const sgx_ias_report_t & RaClientCommLayer::GetIasReport() const
{
	return m_origSession->m_session.m_iasReport;
}

std::shared_ptr<const RaClientSession> RaClientCommLayer::GetOrigSession() const
{
	return m_origSession;
}

const RaSession & Decent::Sgx::RaClientCommLayer::GetCurrSession() const
{
	return *m_currSession;
}

RaClientCommLayer::RaClientCommLayer(ConnectionBase& connectionPtr, std::pair<std::shared_ptr<const RaClientSession>, std::unique_ptr<RaSession> > session) :
	RaClientCommLayer(connectionPtr, session.first, std::move(session.second))
{
}

RaClientCommLayer::RaClientCommLayer(ConnectionBase& connectionPtr, std::shared_ptr<const RaClientSession> origSession, std::unique_ptr<RaSession> currSession) :
	AesGcmCommLayer(currSession->m_secretKey, currSession->m_maskingKey, &connectionPtr),
	m_origSession(origSession),
	m_currSession(std::move(currSession))
{
}
