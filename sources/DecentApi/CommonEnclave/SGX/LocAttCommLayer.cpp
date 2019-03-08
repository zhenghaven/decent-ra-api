#include "LocAttCommLayer.h"

#include <sgx_dh.h>

#include "../../Common/Common.h"
#include "../../Common/make_unique.h"
#include "../../Common/Net/Connection.h"

using namespace Decent;
using namespace Decent::Sgx;
using namespace Decent::Net;

LocAttCommLayer::LocAttCommLayer(void * const connectionPtr, bool isInitiator) :
	LocAttCommLayer(std::move(DoHandShake(connectionPtr, isInitiator)))
{
}

LocAttCommLayer::LocAttCommLayer(LocAttCommLayer && other) :
	AesGcmCommLayer(std::forward<AesGcmCommLayer>(other)),
	m_identity(std::move(other.m_identity)),
	m_isHandShaked(other.m_isHandShaked)
{
	other.m_isHandShaked = false;
}

LocAttCommLayer::~LocAttCommLayer()
{
}

LocAttCommLayer::operator bool() const
{
	return AesGcmCommLayer::operator bool() && m_isHandShaked;
}

const sgx_dh_session_enclave_identity_t* LocAttCommLayer::GetIdentity() const
{
	return m_identity.get();
}

LocAttCommLayer::LocAttCommLayer(std::pair<std::unique_ptr<General128BitKey>, std::unique_ptr<sgx_dh_session_enclave_identity_t>> keyAndId) :
	LocAttCommLayer(keyAndId.first, keyAndId.second, keyAndId.first && keyAndId.second)
{
}

LocAttCommLayer::LocAttCommLayer(std::unique_ptr<General128BitKey>& key, std::unique_ptr<sgx_dh_session_enclave_identity_t>& id, bool isValid) :
	AesGcmCommLayer(isValid ? std::move(*key) : General128BitKey()),
	m_isHandShaked(isValid),
	m_identity(std::move(id))
{
}

std::pair<std::unique_ptr<General128BitKey>, std::unique_ptr<sgx_dh_session_enclave_identity_t> > LocAttCommLayer::DoHandShake(void * const connectionPtr, bool isInitiator)
{
	std::pair<std::unique_ptr<General128BitKey>, std::unique_ptr<sgx_dh_session_enclave_identity_t> > retValue;
	std::unique_ptr<General128BitKey> keyPtr(Tools::make_unique<General128BitKey>());
	std::unique_ptr<sgx_dh_session_enclave_identity_t> idPtr(Tools::make_unique<sgx_dh_session_enclave_identity_t>());

	sgx_dh_session_t session;
	sgx_status_t enclaveRet = SGX_SUCCESS;
	std::string inMsgBuf;
	std::string outMsgBuf;

	try
	{
		if (isInitiator)
		{
			if (sgx_dh_init_session(SGX_DH_SESSION_INITIATOR, &session) != SGX_SUCCESS)
			{
				return std::move(retValue);
			}

			sgx_dh_msg2_t msg2;
			std::memset(&msg2, 0, sizeof(msg2));

			StatConnection::ReceivePack(connectionPtr, inMsgBuf);
			if (inMsgBuf.size() != sizeof(sgx_dh_msg1_t) ||
				sgx_dh_initiator_proc_msg1(reinterpret_cast<const sgx_dh_msg1_t*>(inMsgBuf.data()), &msg2, &session) != SGX_SUCCESS)
			{
				return std::move(retValue);
			}

			StatConnection::SendAndReceivePack(connectionPtr, &msg2, sizeof(msg2), inMsgBuf);
			if (inMsgBuf.size() != sizeof(sgx_dh_msg3_t) ||
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

			if (sgx_dh_responder_gen_msg1(&msg1, &session) != SGX_SUCCESS)
			{

			}

			StatConnection::SendAndReceivePack(connectionPtr, &msg1, sizeof(sgx_dh_msg1_t), inMsgBuf);
			if (inMsgBuf.size() != sizeof(sgx_dh_msg2_t) ||
				sgx_dh_responder_proc_msg2(reinterpret_cast<const sgx_dh_msg2_t*>(inMsgBuf.data()), &msg3, &session,
					reinterpret_cast<sgx_ec_key_128bit_t*>(keyPtr->data()), idPtr.get()) != SGX_SUCCESS)
			{
				return std::move(retValue);
			}

			StatConnection::SendPack(connectionPtr, &msg3, sizeof(msg3));
		}
	}
	catch (const std::exception&)
	{
		return std::move(retValue);
	}

	retValue.first.swap(keyPtr);
	retValue.second.swap(idPtr);

	return std::move(retValue);
}
