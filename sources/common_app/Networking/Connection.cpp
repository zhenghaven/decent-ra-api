#include "Connection.h"
#include "../../common/Connection.h"

bool StaticConnection::Send(void* const connection, const std::string& inMsg)
{
	return StaticConnection::Send(connection, inMsg.data(), inMsg.size());
}

bool StaticConnection::Send(void* const connection, const void* const data, const size_t dataLen)
{
	if (!connection)
	{
		return false;
	}

	return reinterpret_cast<Connection*>(connection)->Send(data, dataLen) == dataLen;
}

int StaticConnection::SendRaw(void * const connection, const void * const data, const size_t dataLen)
{
	return static_cast<int>(reinterpret_cast<Connection*>(connection)->SendRaw(data, dataLen));
}

bool StaticConnection::Receive(void* const connection, std::string& outMsg)
{
	if (!connection)
	{
		return false;
	}

	return reinterpret_cast<Connection*>(connection)->Receive(outMsg) > 0;
}

int StaticConnection::ReceiveRaw(void * const connection, void * const buf, const size_t bufLen)
{
	return static_cast<int>(reinterpret_cast<Connection*>(connection)->ReceiveRaw(buf, bufLen));
}

extern "C" size_t ocall_connection_send(void* const ptr, const char* msg, size_t size)
{
	if (!ptr || !msg)
	{
		return 0;
	}

	return reinterpret_cast<Connection*>(ptr)->Send(msg, size);
}

extern "C" size_t ocall_connection_receive(void* const ptr, char** msg)
{
	if (!ptr || !msg)
	{
		return 0;
	}

	return reinterpret_cast<Connection*>(ptr)->Receive(*msg);
}

extern "C" void ocall_connection_clean_recv_buffer(char* ptr)
{
	delete[] ptr;
}

extern "C" size_t ocall_connection_send_raw(void* const ptr, const char* msg, size_t size)
{
	if (!ptr || !msg)
	{
		return 0;
	}

	return reinterpret_cast<Connection*>(ptr)->SendRaw(msg, size);
}

extern "C" size_t ocall_connection_receive_raw(void* const ptr, char* buf, size_t buf_size)
{
	if (!ptr || !buf)
	{
		return 0;
	}

	return reinterpret_cast<Connection*>(ptr)->ReceiveRaw(buf, buf_size);
}
