#include "LocAttCommLayer.h"

#include <sgx_dh.h>

#include "../../Common/Common.h"
#include "../../Common/make_unique.h"
#include "../../Common/Net/Connection.h"
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

LocAttCommLayer::LocAttCommLayer(void * const connectionPtr, bool isInitiator) :
	LocAttCommLayer(std::move(Handshake(connectionPtr, isInitiator)))
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

LocAttCommLayer::operator bool() const
{
	return AesGcmCommLayer::operator bool() && m_identity;
}

const sgx_dh_session_enclave_identity_t& LocAttCommLayer::GetIdentity() const
{
	return *m_identity;
}

LocAttCommLayer::LocAttCommLayer(std::pair<std::unique_ptr<General128BitKey>, std::unique_ptr<sgx_dh_session_enclave_identity_t> > resultPair) :
	LocAttCommLayer(std::move(resultPair.first), std::move(resultPair.second))
{
}

LocAttCommLayer::LocAttCommLayer(std::unique_ptr<General128BitKey> key, std::unique_ptr<sgx_dh_session_enclave_identity_t> identity) :
	AesGcmCommLayer(*key),
	m_identity(std::move(identity))
{
}

void LocAttCommLayer::InitiatorHandshake(void * const connectionPtr, General128BitKey& outKey, sgx_dh_session_enclave_identity_t& outIdentity)
{
	sgx_dh_session_t session;
	std::string inMsgBuf;

	CHECK_SGX_SDK_RESULT(sgx_dh_init_session(SGX_DH_SESSION_INITIATOR, &session), "Failed to initiate DH session.");

	sgx_dh_msg2_t msg2;
	std::memset(&msg2, 0, sizeof(msg2));

	StatConnection::ReceivePack(connectionPtr, inMsgBuf);

	ASSERT_BOOL_RESULT(inMsgBuf.size() == sizeof(sgx_dh_msg1_t), "Received message 1 has unexpected size.");
	CHECK_SGX_SDK_RESULT(sgx_dh_initiator_proc_msg1(CastPtr<sgx_dh_msg1_t>(inMsgBuf.data()), &msg2, &session), "Failed to process message 1.");

	StatConnection::SendAndReceivePack(connectionPtr, &msg2, sizeof(msg2), inMsgBuf);

	ASSERT_BOOL_RESULT(inMsgBuf.size() == sizeof(sgx_dh_msg3_t), "Received message 3 has unexpected size.");
	CHECK_SGX_SDK_RESULT(sgx_dh_initiator_proc_msg3(CastPtr<sgx_dh_msg3_t>(inMsgBuf.data()), &session,
		CastPtr<sgx_ec_key_128bit_t>(outKey.data()), &outIdentity), "Failed to process message 3.");
}

void LocAttCommLayer::ResponderHandshake(void * const connectionPtr, General128BitKey& outKey, sgx_dh_session_enclave_identity_t& outIdentity)
{
	sgx_dh_session_t session;
	std::string inMsgBuf;

	CHECK_SGX_SDK_RESULT(sgx_dh_init_session(SGX_DH_SESSION_RESPONDER, &session), "Failed to initiate DH session.");

	sgx_dh_msg1_t msg1;
	sgx_dh_msg3_t msg3;
	std::memset(&msg1, 0, sizeof(msg1));
	std::memset(&msg3, 0, sizeof(msg3));

	CHECK_SGX_SDK_RESULT(sgx_dh_responder_gen_msg1(&msg1, &session), "Failed to generate message 1.");

	StatConnection::SendAndReceivePack(connectionPtr, &msg1, sizeof(sgx_dh_msg1_t), inMsgBuf);

	ASSERT_BOOL_RESULT(inMsgBuf.size() == sizeof(sgx_dh_msg2_t), "Received message 2 has unexpected size.");
	CHECK_SGX_SDK_RESULT(sgx_dh_responder_proc_msg2(CastPtr<sgx_dh_msg2_t>(inMsgBuf.data()), &msg3, &session,
		CastPtr<sgx_ec_key_128bit_t>(outKey.data()), &outIdentity), "Failed to process message 2.");

	StatConnection::SendPack(connectionPtr, &msg3, sizeof(msg3));
}

std::pair<std::unique_ptr<General128BitKey>, std::unique_ptr<sgx_dh_session_enclave_identity_t> > LocAttCommLayer::Handshake(void * const connectionPtr, bool isInitiator)
{
	std::pair<std::unique_ptr<General128BitKey>, std::unique_ptr<sgx_dh_session_enclave_identity_t> > retValue =
		std::make_pair(Tools::make_unique<General128BitKey>(), Tools::make_unique<sgx_dh_session_enclave_identity_t>());

	if (isInitiator)
	{
		InitiatorHandshake(connectionPtr, *retValue.first, *retValue.second);
	}
	else
	{
		ResponderHandshake(connectionPtr, *retValue.first, *retValue.second);
	}

	return std::move(retValue);
}
