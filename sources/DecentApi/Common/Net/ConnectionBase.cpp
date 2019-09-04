#include "ConnectionBase.h"

#include "NetworkException.h"

using namespace Decent::Net;

#define CHECK_CONNECTION_PTR(X) if (!X) { throw Decent::Net::Exception("Connection pointer is null!"); }

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
