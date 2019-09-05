#include "LocAttCommLayer.h"

#include <sgx_dh.h>

#include "../../Common/Common.h"
#include "../../Common/make_unique.h"
#include "../../Common/Net/ConnectionBase.h"
#include "../../Common/Net/NetworkException.h"
#include "../../Common/MbedTls/Kdf.h"

using namespace Decent;
using namespace Decent::Sgx;
using namespace Decent::Net;

#define CHECK_SGX_SDK_RESULT(X, MSG) if((X) != SGX_SUCCESS) { throw Decent::Net::Exception("Local Attestation failed: " MSG); }
#define ASSERT_BOOL_RESULT(X, MSG) if(!(X)) { throw Decent::Net::Exception("Local Attestation failed: " MSG); }

namespace
{
	template<typename T>
	static inline T* CastPtr(void* ptr)
	{
		return reinterpret_cast<T*>(ptr);
	}

	template<typename T>
	static inline const T* CastPtr(const void* ptr)
	{
		return reinterpret_cast<const T*>(ptr);
	}

	G128BitSecretKeyWrap DeriveSK(const G128BitSecretKeyWrap& aeKey)
	{
		using namespace Decent::MbedTlsObj;

		G128BitSecretKeyWrap sk;
		CKDF<CipherType::AES, GENERAL_128BIT_16BYTE_SIZE, CipherMode::GCM>(aeKey, "SK", sk);
		return sk;
	}
}

LocAttCommLayer::LocAttCommLayer(ConnectionBase& cnt, bool isInitiator) :
	LocAttCommLayer(Handshake(cnt, isInitiator), cnt)
{
}

LocAttCommLayer::LocAttCommLayer(LocAttCommLayer && other) :
	AesGcmCommLayer(std::forward<AesGcmCommLayer>(other)),
	m_session(std::move(other.m_session))
{
}

LocAttCommLayer::~LocAttCommLayer()
{
}

bool LocAttCommLayer::IsValid() const
{
	return AesGcmCommLayer::IsValid() && m_session;
}

const sgx_dh_session_enclave_identity_t& LocAttCommLayer::GetIdentity() const
{
	return *(m_session->m_id);
}

LocAttCommLayer::LocAttCommLayer(std::unique_ptr<LocAttSession> session, Net::ConnectionBase& cnt) :
	AesGcmCommLayer(DeriveSK(session->m_aek), &cnt),
	m_session(std::move(session))
{
}

std::unique_ptr<LocAttSession> LocAttCommLayer::InitiatorHandshake(ConnectionBase& cnt)
{
	sgx_dh_session_t session;

	CHECK_SGX_SDK_RESULT(sgx_dh_init_session(SGX_DH_SESSION_INITIATOR, &session), "Failed to initiate DH session.");

	sgx_dh_msg2_t msg2;
	std::memset(&msg2, 0, sizeof(msg2));

	std::vector<uint8_t> inBinBuf = cnt.RecvContainer<std::vector<uint8_t> >();

	ASSERT_BOOL_RESULT(inBinBuf.size() == sizeof(sgx_dh_msg1_t), "Received message 1 has unexpected size.");
	CHECK_SGX_SDK_RESULT(sgx_dh_initiator_proc_msg1(CastPtr<sgx_dh_msg1_t>(inBinBuf.data()), &msg2, &session), "Failed to process message 1.");

	inBinBuf = cnt.SendAndRecvPack(&msg2, sizeof(msg2));

	std::unique_ptr<LocAttSession> resSession = Tools::make_unique<LocAttSession>();

	ASSERT_BOOL_RESULT(inBinBuf.size() == sizeof(sgx_dh_msg3_t), "Received message 3 has unexpected size.");
	CHECK_SGX_SDK_RESULT(
		sgx_dh_initiator_proc_msg3(
			CastPtr<sgx_dh_msg3_t>(inBinBuf.data()),
			&session,
			CastPtr<sgx_ec_key_128bit_t>(resSession->m_aek.m_key.data()),
			resSession->m_id.get()),
		"Failed to process local attestation message 3.");

	return std::move(resSession);
}

std::unique_ptr<LocAttSession> LocAttCommLayer::ResponderHandshake(ConnectionBase& cnt)
{
	sgx_dh_session_t session;

	CHECK_SGX_SDK_RESULT(sgx_dh_init_session(SGX_DH_SESSION_RESPONDER, &session), "Failed to initiate DH session.");

	sgx_dh_msg1_t msg1;
	sgx_dh_msg3_t msg3;
	std::memset(&msg1, 0, sizeof(msg1));
	std::memset(&msg3, 0, sizeof(msg3));

	CHECK_SGX_SDK_RESULT(sgx_dh_responder_gen_msg1(&msg1, &session), "Failed to generate message 1.");

	std::vector<uint8_t> inBinBuf = cnt.SendAndRecvPack(&msg1, sizeof(sgx_dh_msg1_t));

	std::unique_ptr<LocAttSession> resSession = Tools::make_unique<LocAttSession>();

	ASSERT_BOOL_RESULT(inBinBuf.size() == sizeof(sgx_dh_msg2_t), "Received message 2 has unexpected size.");
	CHECK_SGX_SDK_RESULT(
		sgx_dh_responder_proc_msg2(
			CastPtr<sgx_dh_msg2_t>(inBinBuf.data()),
			&msg3,
			&session,
			CastPtr<sgx_ec_key_128bit_t>(resSession->m_aek.m_key.data()),
			resSession->m_id.get()),
		"Failed to process local attestation message 2.");

	cnt.SendPack(&msg3, sizeof(msg3));

	return std::move(resSession);
}

std::unique_ptr<LocAttSession> LocAttCommLayer::Handshake(ConnectionBase& cnt, bool isInitiator)
{
	if (isInitiator)
	{
		return InitiatorHandshake(cnt);
	}
	else
	{
		return ResponderHandshake(cnt);
	}
}
