#pragma once

namespace Decent
{
	class CertContainer;

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

	private:
		CertContainer & m_certContainer;
	};
}
