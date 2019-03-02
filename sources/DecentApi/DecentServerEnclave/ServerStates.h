#pragma once

#include "../Common/Ra/States.h"
#include "ServerCertContainer.h"

namespace Decent
{
	namespace Ra
	{
		class ServerStates : public States
		{
		public:
			typedef const WhiteList::Loaded& (*GetLoadedWlFunc)(WhiteList::Loaded*);

		public:
			ServerStates(ServerCertContainer & certCntnr, KeyContainer & keyCntnr, WhiteList::DecentServer & serverWl, const WhiteList::HardCoded & hardCodedWl, GetLoadedWlFunc getLoadedFunc) :
				States(certCntnr, keyCntnr, serverWl, hardCodedWl, getLoadedFunc),
				m_certContainer(certCntnr)
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

		private:
			ServerCertContainer & m_certContainer;
		};
	}
	
}
