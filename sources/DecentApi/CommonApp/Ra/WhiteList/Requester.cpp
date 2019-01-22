#include "Requester.h"

#include <json/json.h>

#include "../Messages.h"
#include "../../Net/Connection.h"

using namespace Decent::Ra::WhiteList;
using namespace Decent::Net;

const Requester & Requester::Get()
{
	static Requester inst;
	return inst;
}

Requester::~Requester()
{
}

bool Requester::SendRequest(Connection & connection) const
{
	using namespace Decent::Ra::Message;

	connection.SendPack(LoadWhiteList(m_key, ConstructWhiteList()));
	return true;
}

std::string Requester::ConstructWhiteList() const
{
	Json::Value root;

	for (auto it = m_whiteList.begin(); it != m_whiteList.end(); ++it)
	{
		root[it->first] = it->second;
	}
	return root.toStyledString();
}
