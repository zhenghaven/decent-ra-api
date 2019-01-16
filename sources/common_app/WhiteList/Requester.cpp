#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_APP_INTERNAL

#include "Requester.h"

#include <json/json.h>

#include "../Decent/Messages.h"
#include "../Networking/Connection.h"

using namespace Decent::WhiteList;

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
	using namespace Decent::Message;

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

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL
