#include "../../Common/Net/Connection.h"

#include <string.h>

#include "edl_decent_net.h"
#include "edl_decent_tools.h"

using namespace Decent::Net;

bool StatConnection::SendPack(void* const connection, const std::string& inMsg)
{
	return StatConnection::SendPack(connection, inMsg.data(), inMsg.size());
}

bool StatConnection::SendPack(void * const connection, const void * const data, const size_t dataLen)
{
	int sentRes = 0;
	sgx_status_t enclaveRet = ocall_decent_net_cnet_send_pack(&sentRes, connection, reinterpret_cast<const char*>(data), dataLen);

	return enclaveRet == SGX_SUCCESS && sentRes;
}

int StatConnection::SendRaw(void * const connection, const void * const data, const size_t dataLen)
{
	size_t sentSize = 0;
	sgx_status_t enclaveRet = ocall_decent_net_cnet_send_raw(&sentSize, connection, reinterpret_cast<const char*>(data), dataLen);

	return enclaveRet == SGX_SUCCESS ? static_cast<int>(sentSize) : -1;
}

bool StatConnection::ReceivePack(void* const connection, std::string& outMsg)
{
	size_t size = 0;
	char* msgPtr = nullptr;

	sgx_status_t enclaveRet = ocall_decent_net_cnet_recv_pack(&size, connection, &msgPtr);
	if (enclaveRet != SGX_SUCCESS || size == 0)
	{
		return false;
	}

	outMsg.resize(size);
	std::memcpy(&outMsg[0], msgPtr, size);

	ocall_decent_tools_del_buf_char(msgPtr);

	return true;
}

int StatConnection::ReceiveRaw(void * const connection, void * const buf, const size_t bufLen)
{
	size_t recvSize = 0;
	sgx_status_t enclaveRet = ocall_decent_net_cnet_recv_raw(&recvSize, connection, reinterpret_cast<char*>(buf), bufLen);

	return enclaveRet == SGX_SUCCESS ? static_cast<int>(recvSize) : -1;
}

bool StatConnection::SendAndReceivePack(void* const connection, const void* const inData, const size_t inDataLen, std::string& outMsg)
{
	size_t size = 0;
	char* msgPtr = nullptr;
	int retVal = 0;

	sgx_status_t enclaveRet = ocall_decent_net_cnet_send_and_recv_pack(&retVal, connection, reinterpret_cast<const char*>(inData), inDataLen, &msgPtr, &size);
	if (enclaveRet != SGX_SUCCESS || !retVal)
	{
		return false;
	}

	outMsg.resize(size);
	std::memcpy(&outMsg[0], msgPtr, size);

	ocall_decent_tools_del_buf_char(msgPtr);

	return true;
}
