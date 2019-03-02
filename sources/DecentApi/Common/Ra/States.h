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
			class HardCoded;
		}

		class States
		{
		public:
			typedef const WhiteList::Loaded& (*GetLoadedWlFunc)(WhiteList::Loaded*);

		public:
			States(CertContainer & certCntnr, KeyContainer & keyCntnr, WhiteList::DecentServer & serverWl, const WhiteList::HardCoded & hardCodedWl, GetLoadedWlFunc getLoadedFunc) :
				m_certContainer(certCntnr),
				m_keyContainer(keyCntnr),
				m_serverWhiteList(serverWl),
				m_hardCodedWhiteList(hardCodedWl),
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

			const WhiteList::HardCoded& GetHardCodedWhiteList() const
			{
				return m_hardCodedWhiteList;
			}

			const WhiteList::Loaded& GetLoadedWhiteList(WhiteList::Loaded* loadedPtr = nullptr) const
			{
				return (*m_getLoadedFunc)(loadedPtr);
			}

		private:
			CertContainer & m_certContainer;
			KeyContainer & m_keyContainer;
			WhiteList::DecentServer & m_serverWhiteList;
			const WhiteList::HardCoded & m_hardCodedWhiteList;
			GetLoadedWlFunc m_getLoadedFunc;
		};
	}
	
}
