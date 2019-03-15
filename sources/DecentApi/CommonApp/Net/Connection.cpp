#include "Connection.h"
#include "../../Common/Net/Connection.h"

#include <json/json.h>

#include "SmartMessages.h"
#include "../../Common/Net/NetworkException.h"
#include "../../Common/Tools/JsonTools.h"

using namespace Decent::Net;
using namespace Decent::Tools;

#define CHECK_CONNECTION_PTR(X) if (!X) { throw Decent::Net::Exception("Connection pointer is null!"); }

void StatConnection::SendPack(void* const connection, const void* const data, const size_t dataLen)
{
	CHECK_CONNECTION_PTR(connection);

	reinterpret_cast<Connection*>(connection)->SendPack(data, dataLen);
}

size_t StatConnection::SendRaw(void * const connection, const void * const data, const size_t dataLen)
{
	CHECK_CONNECTION_PTR(connection);

	return reinterpret_cast<Connection*>(connection)->SendRaw(data, dataLen);
}

void StatConnection::ReceivePack(void* const connection, std::string& outMsg)
{
	CHECK_CONNECTION_PTR(connection);

	reinterpret_cast<Connection*>(connection)->ReceivePack(outMsg);
}

size_t StatConnection::ReceiveRaw(void * const connection, void * const buf, const size_t bufLen)
{
	CHECK_CONNECTION_PTR(connection);

	return reinterpret_cast<Connection*>(connection)->ReceiveRaw(buf, bufLen);
}

void StatConnection::ReceivePack(void * const connection, std::vector<uint8_t>& outMsg)
{
	CHECK_CONNECTION_PTR(connection);

	reinterpret_cast<Connection*>(connection)->ReceivePack(outMsg);
}

void StatConnection::SendAndReceivePack(void * const connection, const void * const inData, const size_t inDataLen, std::string & outMsg)
{
	reinterpret_cast<Connection*>(connection)->SendPack(inData, inDataLen);
	reinterpret_cast<Connection*>(connection)->ReceivePack(outMsg);
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

void Connection::SendPack(const SmartMessages & msg)
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

void Connection::ReceivePack(Json::Value & msg)
{
	std::string buffer;
	ReceivePack(buffer);
	ParseStr2Json(msg, buffer);
}
