#include "Connection.h"

#include "SmartMessages.h"

using namespace Decent::Net;

void Connection::SendSmartMsg(const SmartMessages & msg)
{
	SendPack(msg.ToJsonString());
}
