#pragma once

#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_APP_INTERNAL

#include <string>
#include <map>

class Connection;

namespace Decent
{
	namespace WhiteList
	{
		class Requester
		{
		public:
			static const Requester& Get();

			Requester();
			virtual ~Requester();

			virtual bool SendRequest(Connection& connection) const;

		protected:
			std::string ConstructWhiteList() const;

		private:
			const std::string m_key;
			const std::map<std::string, std::string> m_whiteList;
		};
	}
}

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL
