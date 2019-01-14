#pragma once

namespace Decent
{
	class CertContainer;
	namespace WhiteList
	{
		class DecentServer;
	}

	class States
	{
	public:
		static States& Get()
		{
			static States inst;
			return inst;
		}

		States();

		virtual ~States()
		{
		}

		CertContainer& GetCertContainer()
		{
			return m_certContainer;
		}

		const CertContainer& GetCertContainer() const
		{
			return m_certContainer;
		}

		WhiteList::DecentServer& GetServerWhiteList()
		{
			return m_serverWhiteList;
		}

		const WhiteList::DecentServer& GetServerWhiteList() const
		{
			return m_serverWhiteList;
		}

	private:
		CertContainer & m_certContainer;
		WhiteList::DecentServer & m_serverWhiteList;
	};
}
