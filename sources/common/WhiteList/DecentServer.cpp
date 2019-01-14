#include "DecentServer.h"

using namespace Decent::WhiteList;

DecentServer & Decent::WhiteList::DecentServer::Get()
{
	static DecentServer inst;
	return inst;
}

Decent::WhiteList::DecentServer::~DecentServer()
{
}

Decent::WhiteList::DecentServer::DecentServer()
{
}
