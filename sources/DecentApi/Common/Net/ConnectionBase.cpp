#include "ConnectionBase.h"

#include "NetworkException.h"

using namespace Decent::Net;

#define CHECK_CONNECTION_PTR(X) if (!X) { throw Decent::Net::Exception("Connection pointer is null!"); }

void ConnectionBase::SendRawGuarantee(const void * const dataPtr, const size_t size)
{
	size_t sentSize = 0;
	while (sentSize < size)
	{
		sentSize += SendRaw(reinterpret_cast<const uint8_t*>(dataPtr) + sentSize, size - sentSize);
	}
}

void ConnectionBase::SendPack(const void * const dataPtr, const size_t size)
{
	uint64_t packSize = size;
	SendRawGuarantee(&packSize, sizeof(uint64_t));
	SendRawGuarantee(dataPtr, packSize);
}

void ConnectionBase::ReceiveRawGuarantee(void * const bufPtr, const size_t size)
{
	size_t recvSize = 0;
	while (recvSize < size)
	{
		recvSize += ReceiveRaw(reinterpret_cast<uint8_t*>(bufPtr) + recvSize, size - recvSize);
	}
}

size_t ConnectionBase::ReceivePack(char *& dest)
{
	uint64_t packSize = 0;
	ReceiveRawGuarantee(&packSize, sizeof(packSize));

	dest = new char[static_cast<size_t>(packSize)];
	ReceiveRawGuarantee(dest, static_cast<size_t>(packSize));
	return static_cast<size_t>(packSize);
}

void Decent::Net::ConnectionBase::ReceivePack(std::string & outMsg)
{
	uint64_t packSize = 0;
	ReceiveRawGuarantee(&packSize, sizeof(packSize));

	outMsg.resize(static_cast<size_t>(packSize));
	ReceiveRawGuarantee(&outMsg[0], outMsg.size());
}

void Decent::Net::ConnectionBase::ReceivePack(std::vector<uint8_t>& outMsg)
{
	uint64_t packSize = 0;
	ReceiveRawGuarantee(&packSize, sizeof(packSize));

	outMsg.resize(static_cast<size_t>(packSize));
	ReceiveRawGuarantee(&outMsg[0], outMsg.size());
}

void ConnectionBase::SendAndReceivePack(const void * const inData, const size_t inDataLen, std::string & outMsg)
{
	SendPack(inData, inDataLen);
	ReceivePack(outMsg);
}

int Decent::Net::ConnectionBase::SendRawCallback(void * const connection, const void * const data, const size_t dataLen) noexcept
{
	try
	{
		CHECK_CONNECTION_PTR(connection);
		return static_cast<int>(static_cast<ConnectionBase*>(connection)->SendRaw(data, dataLen));
	}
	catch (const std::exception&)
	{
		return -1;
	}
}

int Decent::Net::ConnectionBase::ReceiveRawCallback(void * const connection, void * const buf, const size_t bufLen) noexcept
{
	try
	{
		CHECK_CONNECTION_PTR(connection);
		return static_cast<int>(static_cast<ConnectionBase*>(connection)->ReceiveRaw(buf, bufLen));
	}
	catch (const std::exception&)
	{
		return -1;
	}
}
