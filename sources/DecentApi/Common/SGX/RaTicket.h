#pragma once

#include <vector>

#include "../GeneralKeyTypes.h"
#include "sgx_structs.h"

namespace Decent
{
	namespace Sgx
	{
		struct RaSession
		{
			General128BitKey m_secretKey;
			uint8_t m_iasReport[sizeof(sgx_ias_report_t)];

			sgx_ias_report_t& GetReport()
			{
				return *reinterpret_cast<sgx_ias_report_t*>(m_iasReport);
			}

			const sgx_ias_report_t& GetReport() const
			{
				return *reinterpret_cast<const sgx_ias_report_t*>(m_iasReport);
			}
		};

		struct RaClientSession
		{
			std::vector<uint8_t> m_ticket;
			RaSession m_session;
		};
	}
}
