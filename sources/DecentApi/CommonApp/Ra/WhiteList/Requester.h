#pragma once

#include <string>
#include <map>

namespace Decent
{
	namespace Net
	{
		class Connection;
	}

	namespace Ra
	{
		namespace WhiteList
		{
			class Requester
			{
			public:
				static const Requester& Get();

				Requester();
				virtual ~Requester();

				virtual bool SendRequest(Net::Connection& connection) const;

				const std::string& GetKey() const { return m_key; }

			protected:
				std::string ConstructWhiteList() const;

			private:
				const std::string m_key;
				const std::map<std::string, std::string> m_whiteList;
			};
		}
	}
}
