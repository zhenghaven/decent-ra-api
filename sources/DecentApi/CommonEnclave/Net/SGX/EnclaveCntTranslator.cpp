//#if ENCLAVE_PLATFORM_SGX

#include "../../../Common/Net/NetworkException.h"
#include "../../SGX/edl_decent_net.h"
#include "../../SGX/edl_decent_tools.h"
#include "../EnclaveCntTranslator.h"

using namespace Decent::Net;

#define CHECK_SGX_ERROR(X) if (X != SGX_SUCCESS) { throw Decent::Net::Exception("OCall to send message pack failed with SGX error code: " + std::to_string(X)); }
#define CHECK_OCALL_BOOL_RET(X) if (!X) { throw Decent::Net::Exception("OCall to send message pack returned false."); }

namespace
{
	struct OcallMessageWrapper
	{
		char* m_ptr;

		OcallMessageWrapper() :
			m_ptr(nullptr)
		{}

		~OcallMessageWrapper()
		{
			ocall_decent_tools_del_buf_char(m_ptr);
		}
	};
}

size_t EnclaveCntTranslator::SendRaw(const void * const dataPtr, const size_t size)
{
	int sentRes = 0;
	size_t sentSize = 0;
	sgx_status_t enclaveRet = ocall_decent_net_cnet_send_raw(&sentRes, &sentSize, m_cntPtr, reinterpret_cast<const char*>(dataPtr), size);

	CHECK_SGX_ERROR(enclaveRet);
	CHECK_OCALL_BOOL_RET(sentRes);
	return sentSize;
}

void EnclaveCntTranslator::SendPack(const void * const dataPtr, const size_t size)
{
	int sentRes = 0;
	sgx_status_t enclaveRet = ocall_decent_net_cnet_send_pack(&sentRes, m_cntPtr, reinterpret_cast<const char*>(dataPtr), size);

	CHECK_SGX_ERROR(enclaveRet);
	CHECK_OCALL_BOOL_RET(sentRes);
}

size_t EnclaveCntTranslator::ReceiveRaw(void * const bufPtr, const size_t size)
{
	int recvRes = 0;
	size_t recvSize = 0;
	sgx_status_t enclaveRet = ocall_decent_net_cnet_recv_raw(&recvRes, &recvSize, m_cntPtr, reinterpret_cast<char*>(bufPtr), size);

	CHECK_SGX_ERROR(enclaveRet);
	CHECK_OCALL_BOOL_RET(recvRes);
	return recvSize;
}

void EnclaveCntTranslator::ReceivePack(std::string & outMsg)
{
	int recvRes = 0;
	size_t size = 0;
	OcallMessageWrapper msg;

	sgx_status_t enclaveRet = ocall_decent_net_cnet_recv_pack(&recvRes, &size, m_cntPtr, &msg.m_ptr);
	CHECK_SGX_ERROR(enclaveRet);
	CHECK_OCALL_BOOL_RET(recvRes);

	outMsg.resize(size);
	std::memcpy(&outMsg[0], msg.m_ptr, size);
}

void EnclaveCntTranslator::ReceivePack(std::vector<uint8_t>& outMsg)
{
	int recvRes = 0;
	size_t size = 0;
	OcallMessageWrapper msg;

	sgx_status_t enclaveRet = ocall_decent_net_cnet_recv_pack(&recvRes, &size, m_cntPtr, &msg.m_ptr);
	CHECK_SGX_ERROR(enclaveRet);
	CHECK_OCALL_BOOL_RET(recvRes);

	outMsg.resize(size);
	std::memcpy(&outMsg[0], msg.m_ptr, size);
}

void EnclaveCntTranslator::SendAndReceivePack(const void * const inData, const size_t inDataLen, std::string & outMsg)
{
	int retVal = 0;
	size_t size = 0;
	OcallMessageWrapper msg;

	sgx_status_t enclaveRet = ocall_decent_net_cnet_send_and_recv_pack(&retVal, m_cntPtr, reinterpret_cast<const char*>(inData), inDataLen, &msg.m_ptr, &size);
	CHECK_SGX_ERROR(enclaveRet);
	CHECK_OCALL_BOOL_RET(retVal);

	outMsg.resize(size);
	std::memcpy(&outMsg[0], msg.m_ptr, size);
}

//#endif //ENCLAVE_PLATFORM_SGX
