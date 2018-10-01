#include "Connection.h"
#include "../../common/Connection.h"

bool StaticConnection::Send(void* const connection, const std::string& inMsg)
{
	if (!connection)
	{
		return false;
	}

	return reinterpret_cast<Connection*>(connection)->Send(inMsg.data(), inMsg.size()) == inMsg.size();
}

bool StaticConnection::Receive(void* const connection, std::string& outMsg)
{
	if (!connection)
	{
		return false;
	}

	return reinterpret_cast<Connection*>(connection)->Receive(outMsg) > 0;
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
