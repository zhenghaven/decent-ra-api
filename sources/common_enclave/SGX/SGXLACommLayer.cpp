#include "SGXLACommLayer.h"

#include <sgx_dh.h>

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
	std::unique_ptr<General128BitKey> keyPtr(new General128BitKey);
	std::unique_ptr<sgx_dh_session_enclave_identity_t> idPtr(new sgx_dh_session_enclave_identity_t);

	sgx_dh_session_t session;
	sgx_status_t enclaveRet = SGX_SUCCESS;
	std::string inMsgBuf;
	std::string outMsgBuf;

	if (isInitiator)
	{
		enclaveRet = sgx_dh_init_session(SGX_DH_SESSION_INITIATOR, &session);
		if (enclaveRet != SGX_SUCCESS)
		{
			return std::move(retValue);
		}

		if (!StaticConnection::ReceivePack(connectionPtr, inMsgBuf) ||
			inMsgBuf.size() != sizeof(sgx_dh_msg1_t))
		{
			return std::move(retValue);
		}
		{
			sgx_dh_msg1_t& inMsg1 = reinterpret_cast<sgx_dh_msg1_t&>(inMsgBuf[0]);
			outMsgBuf.resize(sizeof(sgx_dh_msg2_t));
			sgx_dh_msg2_t& outMsg2 = reinterpret_cast<sgx_dh_msg2_t&>(outMsgBuf[0]);
			enclaveRet = sgx_dh_initiator_proc_msg1(&inMsg1, &outMsg2, &session);
			if (enclaveRet != SGX_SUCCESS)
			{
				return std::move(retValue);
			}
		}

		if (!StaticConnection::SendPack(connectionPtr, outMsgBuf) ||
			!StaticConnection::ReceivePack(connectionPtr, inMsgBuf) ||
			inMsgBuf.size() != sizeof(sgx_dh_msg3_t))
		{
			return std::move(retValue);
		}
		{
			sgx_dh_msg3_t& inMsg3 = reinterpret_cast<sgx_dh_msg3_t&>(inMsgBuf[0]);
			enclaveRet = sgx_dh_initiator_proc_msg3(&inMsg3, &session, reinterpret_cast<sgx_ec_key_128bit_t*>(keyPtr->data()), idPtr.get());
			if (enclaveRet != SGX_SUCCESS)
			{
				return std::move(retValue);
			}
		}
	}
	else
	{
		enclaveRet = sgx_dh_init_session(SGX_DH_SESSION_RESPONDER, &session);
		if (enclaveRet != SGX_SUCCESS)
		{
			return std::move(retValue);
		}

		{
			outMsgBuf.resize(sizeof(sgx_dh_msg1_t));
			sgx_dh_msg1_t& outMsg1 = reinterpret_cast<sgx_dh_msg1_t&>(outMsgBuf[0]);
			enclaveRet = sgx_dh_responder_gen_msg1(&outMsg1, &session);
			if (enclaveRet != SGX_SUCCESS)
			{
				return std::move(retValue);
			}
		}

		if (!StaticConnection::SendPack(connectionPtr, outMsgBuf) ||
			!StaticConnection::ReceivePack(connectionPtr, inMsgBuf) ||
			inMsgBuf.size() != sizeof(sgx_dh_msg2_t))
		{
			return std::move(retValue);
		}
		{
			sgx_dh_msg2_t& inMsg2 = reinterpret_cast<sgx_dh_msg2_t&>(inMsgBuf[0]);
			outMsgBuf.resize(sizeof(sgx_dh_msg3_t));
			sgx_dh_msg3_t& outMsg3 = reinterpret_cast<sgx_dh_msg3_t&>(outMsgBuf[0]);
			enclaveRet = sgx_dh_responder_proc_msg2(&inMsg2, &outMsg3, &session, reinterpret_cast<sgx_ec_key_128bit_t*>(keyPtr->data()), idPtr.get());
			if (enclaveRet != SGX_SUCCESS)
			{
				return std::move(retValue);
			}
		}
		if (!StaticConnection::SendPack(connectionPtr, outMsgBuf))
		{
			return std::move(retValue);
		}
	}

	retValue.first.swap(keyPtr);
	retValue.second.swap(idPtr);

	return std::move(retValue);
}
