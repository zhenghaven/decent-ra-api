#pragma once

#include "../Common/Ra/States.h"
#include "ServerCertContainer.h"

namespace Decent
{
	namespace Ra
	{
		namespace WhiteList
		{
			class AppWhiteListsManager;
		}

		class ServerStates : public States
		{
		public:
			ServerStates(ServerCertContainer & certCntnr, KeyContainer & keyCntnr, WhiteList::DecentServer & serverWl, WhiteList::AppWhiteListsManager & appWlMgr, GetLoadedWlFunc getLoadedFunc) :
				States(certCntnr, keyCntnr, serverWl, getLoadedFunc),
				m_certContainer(certCntnr),
				m_appWlMgr(appWlMgr)
			{}

			virtual ~ServerStates()
			{}

			ServerCertContainer& GetServerCertContainer()
			{
				return m_certContainer;
			}

			const ServerCertContainer& GetServerCertContainer() const
			{
				return m_certContainer;
			}

			WhiteList::AppWhiteListsManager& GetAppWhiteListsManager()
			{
				return m_appWlMgr;
			}

			const WhiteList::AppWhiteListsManager& GetAppWhiteListsManager() const
			{
				return m_appWlMgr;
			}

		private:
			ServerCertContainer & m_certContainer;
			WhiteList::AppWhiteListsManager & m_appWlMgr;
		};
	}
	
}
