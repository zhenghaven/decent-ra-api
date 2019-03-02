#pragma once

#include "../Common/Ra/States.h"
#include "AppCertContainer.h"

namespace Decent
{
	namespace Ra
	{
		class AppStates : public States
		{
		public:
			typedef const WhiteList::Loaded& (*GetLoadedWlFunc)(WhiteList::Loaded*);

		public:
			AppStates(AppCertContainer & certCntnr, KeyContainer & keyCntnr, WhiteList::DecentServer & serverWl, const WhiteList::HardCoded & hardCodedWl, GetLoadedWlFunc getLoadedFunc) :
				States(certCntnr, keyCntnr, serverWl, hardCodedWl, getLoadedFunc),
				m_certContainer(certCntnr)
			{}

			virtual ~AppStates()
			{}

			AppCertContainer& GetAppCertContainer()
			{
				return m_certContainer;
			}

			const AppCertContainer& GetAppCertContainer() const
			{
				return m_certContainer;
			}

		private:
			AppCertContainer & m_certContainer;
		};
	}
	
}
