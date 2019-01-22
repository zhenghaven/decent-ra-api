#pragma once

namespace Decent
{
	namespace Ra
	{
		class AppX509;
		class CertContainer;
		class KeyContainer;

		namespace WhiteList
		{
			class DecentServer;
			class Loaded;
			class HardCoded;
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

			KeyContainer& GetKeyContainer()
			{
				return m_keyContainer;
			}

			const KeyContainer& GetKeyContainer() const
			{
				return m_keyContainer;
			}

			WhiteList::DecentServer& GetServerWhiteList()
			{
				return m_serverWhiteList;
			}

			const WhiteList::DecentServer& GetServerWhiteList() const
			{
				return m_serverWhiteList;
			}

			WhiteList::HardCoded& GetHardCodedWhiteList()
			{
				return m_hardCodedWhiteList;
			}

			const WhiteList::HardCoded& GetHardCodedWhiteList() const
			{
				return m_hardCodedWhiteList;
			}

			const WhiteList::Loaded& GetLoadedWhiteList(Decent::Ra::AppX509* certPtr = nullptr) const;

		private:
			CertContainer & m_certContainer;
			KeyContainer & m_keyContainer;
			WhiteList::DecentServer & m_serverWhiteList;
			WhiteList::HardCoded & m_hardCodedWhiteList;
		};
	}
	
}
