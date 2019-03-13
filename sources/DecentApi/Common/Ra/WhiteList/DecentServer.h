#pragma once

#include <map>
#include <mutex>

#include "../../structs.h"

namespace Decent
{
	namespace Ra
	{
		class ServerX509;
		
		namespace WhiteList
		{
			class DecentServer
			{
			public:
				DecentServer();
				virtual ~DecentServer();

				virtual bool AddTrustedNode(const ServerX509& cert);
				virtual bool IsNodeTrusted(const std::string& key) const;
				virtual bool GetAcceptedTimestamp(const std::string& key, report_timestamp_t& outTime) const;

			protected:
				virtual bool VerifyCertFirstTime(const ServerX509& cert) const;
				virtual bool VerifyCertAfterward(const ServerX509& cert) const;

			private:
				std::map<std::string, report_timestamp_t> m_acceptedNodes;
				mutable std::mutex m_acceptedNodesMutex;
			};
		}
	}
}