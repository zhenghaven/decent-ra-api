#include "../../Common/Net/Connection.h"

#include <string.h>

#include "../../Common/Net/NetworkException.h"
#include "edl_decent_net.h"
#include "edl_decent_tools.h"

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

void StatConnection::SendPack(void * const connection, const void * const data, const size_t dataLen)
{
	int sentRes = 0;
	sgx_status_t enclaveRet = ocall_decent_net_cnet_send_pack(&sentRes, connection, reinterpret_cast<const char*>(data), dataLen);

	CHECK_SGX_ERROR(enclaveRet);
	CHECK_OCALL_BOOL_RET(sentRes);
}

size_t StatConnection::SendRaw(void * const connection, const void * const data, const size_t dataLen)
{
	int sentRes = 0;
	size_t sentSize = 0;
	sgx_status_t enclaveRet = ocall_decent_net_cnet_send_raw(&sentRes, &sentSize, connection, reinterpret_cast<const char*>(data), dataLen);

	CHECK_SGX_ERROR(enclaveRet);
	CHECK_OCALL_BOOL_RET(sentRes);
	return sentSize;
}

void StatConnection::ReceivePack(void* const connection, std::string& outMsg)
{
	int recvRes = 0;
	size_t size = 0;
	OcallMessageWrapper msg;

	sgx_status_t enclaveRet = ocall_decent_net_cnet_recv_pack(&recvRes, &size, connection, &msg.m_ptr);
	CHECK_SGX_ERROR(enclaveRet);
	CHECK_OCALL_BOOL_RET(recvRes);

	outMsg.resize(size);
	std::memcpy(&outMsg[0], msg.m_ptr, size);
}

void StatConnection::ReceivePack(void* const connection, std::vector<uint8_t>& outMsg)
{
	int recvRes = 0;
	size_t size = 0;
	OcallMessageWrapper msg;

	sgx_status_t enclaveRet = ocall_decent_net_cnet_recv_pack(&recvRes, &size, connection, &msg.m_ptr);
	CHECK_SGX_ERROR(enclaveRet);
	CHECK_OCALL_BOOL_RET(recvRes);

	outMsg.resize(size);
	std::memcpy(&outMsg[0], msg.m_ptr, size);
}

size_t StatConnection::ReceiveRaw(void * const connection, void * const buf, const size_t bufLen)
{
	int recvRes = 0;
	size_t recvSize = 0;
	sgx_status_t enclaveRet = ocall_decent_net_cnet_recv_raw(&recvRes, &recvSize, connection, reinterpret_cast<char*>(buf), bufLen);

	CHECK_SGX_ERROR(enclaveRet);
	CHECK_OCALL_BOOL_RET(recvRes);
	return recvSize;
}

void StatConnection::SendAndReceivePack(void* const connection, const void* const inData, const size_t inDataLen, std::string& outMsg)
{
	int retVal = 0;
	size_t size = 0;
	OcallMessageWrapper msg;

	sgx_status_t enclaveRet = ocall_decent_net_cnet_send_and_recv_pack(&retVal, connection, reinterpret_cast<const char*>(inData), inDataLen, &msg.m_ptr, &size);
	CHECK_SGX_ERROR(enclaveRet);
	CHECK_OCALL_BOOL_RET(retVal);

	outMsg.resize(size);
	std::memcpy(&outMsg[0], msg.m_ptr, size);
}
