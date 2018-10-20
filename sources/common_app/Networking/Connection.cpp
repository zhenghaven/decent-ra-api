#include "Connection.h"

#include <stdexcept>

#include <json/json.h>

#include "../Messages.h"
#include "../../common/Connection.h"
#include "../../common/JsonTools.h"

bool StaticConnection::SendPack(void* const connection, const std::string& inMsg)
{
	return StaticConnection::SendPack(connection, inMsg.data(), inMsg.size());
}

bool StaticConnection::SendPack(void* const connection, const void* const data, const size_t dataLen)
{
	if (!connection)
	{
		return false;
	}

	reinterpret_cast<Connection*>(connection)->SendPack(data, dataLen);
	return true;
}

int StaticConnection::SendRaw(void * const connection, const void * const data, const size_t dataLen)
{
	return static_cast<int>(reinterpret_cast<Connection*>(connection)->SendRaw(data, dataLen));
}

bool StaticConnection::ReceivePack(void* const connection, std::string& outMsg)
{
	if (!connection)
	{
		return false;
	}

	reinterpret_cast<Connection*>(connection)->ReceivePack(outMsg);
	return true;
}

int StaticConnection::ReceiveRaw(void * const connection, void * const buf, const size_t bufLen)
{
	return static_cast<int>(reinterpret_cast<Connection*>(connection)->ReceiveRaw(buf, bufLen));
}

bool StaticConnection::SendAndReceivePack(void * const connection, const void * const inData, const size_t inDataLen, std::string & outMsg)
{
	reinterpret_cast<Connection*>(connection)->SendPack(inData, inDataLen);
	reinterpret_cast<Connection*>(connection)->ReceivePack(outMsg);
	return true;
}

extern "C" int ocall_connection_send_pack(void* const ptr, const char* msg, size_t size)
{
	if (!ptr || !msg)
	{
		return false;
	}

	try
	{
		reinterpret_cast<Connection*>(ptr)->SendPack(msg, size);
		return true;
	}
	catch (const std::exception&)
	{
		return false;
	}
}

extern "C" size_t ocall_connection_receive_pack(void* const ptr, char** msg)
{
	if (!ptr || !msg)
	{
		return 0;
	}

	try
	{
		return reinterpret_cast<Connection*>(ptr)->ReceivePack(*msg);
	}
	catch (const std::exception&)
	{
		return 0;
	}
}

extern "C" int ocall_connection_send_and_recv_pack(void* const ptr, const char* in_msg, size_t in_size, char** out_msg, size_t* out_size)
{
	if (!ptr || !in_msg || !out_msg || !out_size)
	{
		return false;
	}

	try
	{
		reinterpret_cast<Connection*>(ptr)->SendPack(in_msg, in_size);
		*out_size = reinterpret_cast<Connection*>(ptr)->ReceivePack(*out_msg);
		return true;
	}
	catch (const std::exception&)
	{
		return false;
	}
}

extern "C" size_t ocall_connection_send_raw(void* const ptr, const char* msg, size_t size)
{
	if (!ptr || !msg)
	{
		return 0;
	}

	try
	{
		return reinterpret_cast<Connection*>(ptr)->SendRaw(msg, size);
	}
	catch (const std::exception&)
	{
		return 0;
	}
}

extern "C" size_t ocall_connection_receive_raw(void* const ptr, char* buf, size_t buf_size)
{
	if (!ptr || !buf)
	{
		return 0;
	}

	try
	{
		return reinterpret_cast<Connection*>(ptr)->ReceiveRaw(buf, buf_size);
	}
	catch (const std::exception&)
	{
		return 0;
	}
}

void Connection::SendRawGuarantee(const void * const dataPtr, const size_t size)
{
	size_t sentSize = 0;
	while (sentSize < size)
	{
		sentSize += SendRaw(reinterpret_cast<const uint8_t*>(dataPtr) + sentSize, size - sentSize);
	}
}

void Connection::SendPack(const void * const dataPtr, const size_t size)
{
	uint64_t packSize = size;
	SendRawGuarantee(&packSize, sizeof(uint64_t));
	SendRawGuarantee(dataPtr, packSize);
}

void Connection::SendPack(const std::string & msg)
{
	SendPack(msg.data(), msg.size());
}

void Connection::SendPack(const std::vector<uint8_t>& msg)
{
	SendPack(msg.data(), msg.size());
}

void Connection::SendPack(const Messages & msg)
{
	SendPack(msg.ToJsonString());
}

void Connection::SendPack(const Json::Value & msg)
{
	SendPack(msg.toStyledString());
}

void Connection::ReceiveRawGuarantee(void * const bufPtr, const size_t size)
{
	size_t recvSize = 0;
	while (recvSize < size)
	{
		recvSize += ReceiveRaw(reinterpret_cast<uint8_t*>(bufPtr) + recvSize, size - recvSize);
	}
}

void Connection::ReceivePack(std::string & msg)
{
	uint64_t packSize = 0;
	ReceiveRawGuarantee(&packSize, sizeof(packSize));

	msg.resize(static_cast<size_t>(packSize));
	ReceiveRawGuarantee(&msg[0], msg.size());
}

void Connection::ReceivePack(std::vector<uint8_t>& msg)
{
	uint64_t packSize = 0;
	ReceiveRawGuarantee(&packSize, sizeof(packSize));

	msg.resize(static_cast<size_t>(packSize));
	ReceiveRawGuarantee(&msg[0], msg.size());
}

size_t Connection::ReceivePack(char *& dest)
{
	uint64_t packSize = 0;
	ReceiveRawGuarantee(&packSize, sizeof(packSize));

	dest = new char[static_cast<size_t>(packSize)];
	ReceiveRawGuarantee(dest, static_cast<size_t>(packSize));
	return static_cast<size_t>(packSize);
}

bool Connection::ReceivePack(Json::Value & msg)
{
	std::string buffer;
	ReceivePack(buffer);
	return ParseStr2Json(msg, buffer);
}
