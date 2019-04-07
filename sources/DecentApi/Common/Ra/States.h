#pragma once

namespace Decent
{
	namespace Ra
	{
		class CertContainer;
		class KeyContainer;

		namespace WhiteList
		{
			class DecentServer;
			class Loaded;
		}

		class States
		{
		public:
			typedef const WhiteList::Loaded& (*GetLoadedWlFunc)(WhiteList::Loaded*);

		public:
			States(CertContainer & certCntnr, KeyContainer & keyCntnr, WhiteList::DecentServer & serverWl, GetLoadedWlFunc getLoadedFunc) :
				m_certContainer(certCntnr),
				m_keyContainer(keyCntnr),
				m_serverWhiteList(serverWl),
				m_getLoadedFunc(getLoadedFunc)
			{}

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

			const WhiteList::Loaded& GetLoadedWhiteList(WhiteList::Loaded* loadedPtr = nullptr) const
			{
				return (*m_getLoadedFunc)(loadedPtr);
			}

		private:
			CertContainer & m_certContainer;
			KeyContainer & m_keyContainer;
			WhiteList::DecentServer & m_serverWhiteList;
			GetLoadedWlFunc m_getLoadedFunc;
		};
	}
	
}
