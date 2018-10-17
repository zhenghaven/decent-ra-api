#include "../../common/Connection.h"

#include <string.h>

#include <Enclave_t.h>

bool StaticConnection::Send(void* const connection, const std::string& inMsg)
{
	return StaticConnection::Send(connection, inMsg.data(), inMsg.size());
}

bool StaticConnection::Send(void * const connection, const void * const data, const size_t dataLen)
{
	size_t sentSize = 0;
	sgx_status_t enclaveRet = ocall_connection_send(&sentSize, connection, reinterpret_cast<const char*>(data), dataLen);

	return enclaveRet == SGX_SUCCESS && sentSize == dataLen;
}

int StaticConnection::SendRaw(void * const connection, const void * const data, const size_t dataLen)
{
	size_t sentSize = 0;
	sgx_status_t enclaveRet = ocall_connection_send_raw(&sentSize, connection, reinterpret_cast<const char*>(data), dataLen);

	return enclaveRet == SGX_SUCCESS ? static_cast<int>(sentSize) : -1;
}

bool StaticConnection::Receive(void* const connection, std::string& outMsg)
{
	size_t size = 0;
	char* msgPtr = nullptr;

	sgx_status_t enclaveRet = ocall_connection_receive(&size, connection, &msgPtr);
	if (enclaveRet != SGX_SUCCESS)
	{
		return false;
	}

	outMsg.resize(size);
	std::memcpy(&outMsg[0], msgPtr, size);

	ocall_connection_clean_recv_buffer(msgPtr);

	return true;
}

int StaticConnection::ReceiveRaw(void * const connection, void * const buf, const size_t bufLen)
{
	size_t recvSize = 0;
	sgx_status_t enclaveRet = ocall_connection_receive_raw(&recvSize, connection, reinterpret_cast<char*>(buf), bufLen);

	return enclaveRet == SGX_SUCCESS ? static_cast<int>(recvSize) : -1;
}
