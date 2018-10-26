#include "SGXLACommLayer.h"

#include <sgx_dh.h>

#include "../../common/CommonTool.h"
#include "../../common/DataCoding.h"
#include "../../common/Connection.h"

SGXLACommLayer::SGXLACommLayer(void * const connectionPtr, bool isInitiator) :
	SGXLACommLayer(std::move(DoHandShake(connectionPtr, isInitiator)))
{
}

SGXLACommLayer::SGXLACommLayer(SGXLACommLayer && other) :
	AESGCMCommLayer(std::forward<AESGCMCommLayer>(other)),
	m_identity(std::move(other.m_identity)),
	m_isHandShaked(other.m_isHandShaked)
{
	other.m_isHandShaked = false;
}

SGXLACommLayer::~SGXLACommLayer()
{
}

SGXLACommLayer::operator bool() const
{
	return AESGCMCommLayer::operator bool() && m_isHandShaked;
}

const sgx_dh_session_enclave_identity_t* SGXLACommLayer::GetIdentity() const
{
	return m_identity.get();
}

SGXLACommLayer::SGXLACommLayer(std::pair<std::unique_ptr<General128BitKey>, std::unique_ptr<sgx_dh_session_enclave_identity_t>> keyAndId) :
	SGXLACommLayer(keyAndId.first, keyAndId.second, keyAndId.first && keyAndId.second)
{
}

SGXLACommLayer::SGXLACommLayer(std::unique_ptr<General128BitKey>& key, std::unique_ptr<sgx_dh_session_enclave_identity_t>& id, bool isValid) :
	AESGCMCommLayer(isValid ? std::move(*key) : General128BitKey()),
	m_isHandShaked(isValid),
	m_identity(std::move(id))
{
}

std::pair<std::unique_ptr<General128BitKey>, std::unique_ptr<sgx_dh_session_enclave_identity_t> > SGXLACommLayer::DoHandShake(void * const connectionPtr, bool isInitiator)
{
	std::pair<std::unique_ptr<General128BitKey>, std::unique_ptr<sgx_dh_session_enclave_identity_t> > retValue;
	std::unique_ptr<General128BitKey> keyPtr(Common::make_unique<General128BitKey>());
	std::unique_ptr<sgx_dh_session_enclave_identity_t> idPtr(Common::make_unique<sgx_dh_session_enclave_identity_t>());

	sgx_dh_session_t session;
	sgx_status_t enclaveRet = SGX_SUCCESS;
	std::string inMsgBuf;
	std::string outMsgBuf;

	if (isInitiator)
	{
		if (sgx_dh_init_session(SGX_DH_SESSION_INITIATOR, &session) != SGX_SUCCESS)
		{
			return std::move(retValue);
		}

		sgx_dh_msg2_t msg2;
		std::memset(&msg2, 0, sizeof(msg2));

		if (!StaticConnection::ReceivePack(connectionPtr, inMsgBuf) ||
			inMsgBuf.size() != sizeof(sgx_dh_msg1_t) ||
			sgx_dh_initiator_proc_msg1(reinterpret_cast<const sgx_dh_msg1_t*>(inMsgBuf.data()), &msg2, &session) != SGX_SUCCESS ||
			!StaticConnection::SendAndReceivePack(connectionPtr, &msg2, sizeof(msg2), inMsgBuf) ||
			inMsgBuf.size() != sizeof(sgx_dh_msg3_t) ||
			sgx_dh_initiator_proc_msg3(reinterpret_cast<const sgx_dh_msg3_t*>(inMsgBuf.data()), &session, 
				reinterpret_cast<sgx_ec_key_128bit_t*>(keyPtr->data()), idPtr.get()) != SGX_SUCCESS)
		{
			return std::move(retValue);
		}
	}
	else
	{
		if (sgx_dh_init_session(SGX_DH_SESSION_RESPONDER, &session) != SGX_SUCCESS)
		{
			return std::move(retValue);
		}

		sgx_dh_msg1_t msg1;
		sgx_dh_msg3_t msg3;
		std::memset(&msg1, 0, sizeof(msg1));
		std::memset(&msg3, 0, sizeof(msg3));

		if (sgx_dh_responder_gen_msg1(&msg1, &session) != SGX_SUCCESS ||
			!StaticConnection::SendAndReceivePack(connectionPtr, &msg1, sizeof(sgx_dh_msg1_t), inMsgBuf) ||
			inMsgBuf.size() != sizeof(sgx_dh_msg2_t) ||
			sgx_dh_responder_proc_msg2(reinterpret_cast<const sgx_dh_msg2_t*>(inMsgBuf.data()), &msg3, &session,
				reinterpret_cast<sgx_ec_key_128bit_t*>(keyPtr->data()), idPtr.get()) != SGX_SUCCESS ||
			!StaticConnection::SendPack(connectionPtr, &msg3, sizeof(msg3)))
		{
			return std::move(retValue);
		}
	}

	retValue.first.swap(keyPtr);
	retValue.second.swap(idPtr);

	return std::move(retValue);
}
