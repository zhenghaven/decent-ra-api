#include "LocAttCommLayer.h"

#include <sgx_dh.h>

#include "../../Common/Common.h"
#include "../../Common/make_unique.h"
#include "../../Common/Net/ConnectionBase.h"
#include "../../Common/Net/NetworkException.h"

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
}

LocAttCommLayer::LocAttCommLayer(ConnectionBase& cnt, bool isInitiator) :
	LocAttCommLayer(std::move(Handshake(cnt, isInitiator)))
{
}

LocAttCommLayer::LocAttCommLayer(LocAttCommLayer && other) :
	AesGcmCommLayer(std::forward<AesGcmCommLayer>(other)),
	m_identity(std::move(other.m_identity))
{
}

LocAttCommLayer::~LocAttCommLayer()
{
}

bool LocAttCommLayer::IsValid() const
{
	return AesGcmCommLayer::IsValid() && m_identity;
}

const sgx_dh_session_enclave_identity_t& LocAttCommLayer::GetIdentity() const
{
	return *m_identity;
}

LocAttCommLayer::LocAttCommLayer(std::pair<std::pair<std::unique_ptr<General128BitKey>, std::unique_ptr<sgx_dh_session_enclave_identity_t> >,
	Net::ConnectionBase*> resultPair) :
	LocAttCommLayer(std::move(resultPair.first.first), std::move(resultPair.first.second), resultPair.second)
{
}

LocAttCommLayer::LocAttCommLayer(std::unique_ptr<General128BitKey> key, std::unique_ptr<sgx_dh_session_enclave_identity_t> identity, Net::ConnectionBase* cnt) :
	AesGcmCommLayer(*key, cnt),
	m_identity(std::move(identity))
{
}

void LocAttCommLayer::InitiatorHandshake(ConnectionBase& cnt, General128BitKey& outKey, sgx_dh_session_enclave_identity_t& outIdentity)
{
	sgx_dh_session_t session;

	CHECK_SGX_SDK_RESULT(sgx_dh_init_session(SGX_DH_SESSION_INITIATOR, &session), "Failed to initiate DH session.");

	sgx_dh_msg2_t msg2;
	std::memset(&msg2, 0, sizeof(msg2));

	std::string inMsgBuf = cnt.RecvContainer<std::string>();

	ASSERT_BOOL_RESULT(inMsgBuf.size() == sizeof(sgx_dh_msg1_t), "Received message 1 has unexpected size.");
	CHECK_SGX_SDK_RESULT(sgx_dh_initiator_proc_msg1(CastPtr<sgx_dh_msg1_t>(inMsgBuf.data()), &msg2, &session), "Failed to process message 1.");

	cnt.SendAndRecvPack(&msg2, sizeof(msg2), inMsgBuf);

	ASSERT_BOOL_RESULT(inMsgBuf.size() == sizeof(sgx_dh_msg3_t), "Received message 3 has unexpected size.");
	CHECK_SGX_SDK_RESULT(sgx_dh_initiator_proc_msg3(CastPtr<sgx_dh_msg3_t>(inMsgBuf.data()), &session,
		CastPtr<sgx_ec_key_128bit_t>(outKey.data()), &outIdentity), "Failed to process message 3.");
}

void LocAttCommLayer::ResponderHandshake(ConnectionBase& cnt, General128BitKey& outKey, sgx_dh_session_enclave_identity_t& outIdentity)
{
	sgx_dh_session_t session;
	std::string inMsgBuf;

	CHECK_SGX_SDK_RESULT(sgx_dh_init_session(SGX_DH_SESSION_RESPONDER, &session), "Failed to initiate DH session.");

	sgx_dh_msg1_t msg1;
	sgx_dh_msg3_t msg3;
	std::memset(&msg1, 0, sizeof(msg1));
	std::memset(&msg3, 0, sizeof(msg3));

	CHECK_SGX_SDK_RESULT(sgx_dh_responder_gen_msg1(&msg1, &session), "Failed to generate message 1.");

	cnt.SendAndRecvPack(&msg1, sizeof(sgx_dh_msg1_t), inMsgBuf);

	ASSERT_BOOL_RESULT(inMsgBuf.size() == sizeof(sgx_dh_msg2_t), "Received message 2 has unexpected size.");
	CHECK_SGX_SDK_RESULT(sgx_dh_responder_proc_msg2(CastPtr<sgx_dh_msg2_t>(inMsgBuf.data()), &msg3, &session,
		CastPtr<sgx_ec_key_128bit_t>(outKey.data()), &outIdentity), "Failed to process message 2.");

	cnt.SendPack(&msg3, sizeof(msg3));
}

std::pair<std::pair<std::unique_ptr<General128BitKey>, std::unique_ptr<sgx_dh_session_enclave_identity_t> >,
	Net::ConnectionBase*> LocAttCommLayer::Handshake(ConnectionBase& cnt, bool isInitiator)
{
	std::pair<std::unique_ptr<General128BitKey>, std::unique_ptr<sgx_dh_session_enclave_identity_t> > retValue =
		std::make_pair(Tools::make_unique<General128BitKey>(), Tools::make_unique<sgx_dh_session_enclave_identity_t>());

	if (isInitiator)
	{
		InitiatorHandshake(cnt, *retValue.first, *retValue.second);
	}
	else
	{
		ResponderHandshake(cnt, *retValue.first, *retValue.second);
	}

	return std::make_pair(std::move(retValue), &cnt);
}
