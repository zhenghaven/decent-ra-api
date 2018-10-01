#include "../../common/Connection.h"

#include <string.h>

#include <Enclave_t.h>

bool StaticConnection::Send(void* const connection, const std::string& inMsg)
{
	size_t size = 0;
	sgx_status_t enclaveRet = ocall_connection_send(&size, connection, inMsg.data(), inMsg.size());

	return enclaveRet == SGX_SUCCESS && size == inMsg.size();
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
