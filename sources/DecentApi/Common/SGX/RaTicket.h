#pragma once

#include <vector>

#include "../GeneralKeyTypes.h"
#include "../RuntimeException.h"
#include "sgx_structs.h"

namespace Decent
{
	namespace Sgx
	{
		struct SgxIasReport
		{
			uint8_t m_iasReport[sizeof(sgx_ias_report_t)];

			SgxIasReport() :
				m_iasReport{ 0 }
			{}

			SgxIasReport(const sgx_ias_report_t& cRpt)
			{
				(*this) = cRpt;
			}

			operator sgx_ias_report_t&()
			{
				return *reinterpret_cast<sgx_ias_report_t*>(m_iasReport);
			}
			
			operator const sgx_ias_report_t&() const
			{
				return *reinterpret_cast<const sgx_ias_report_t*>(m_iasReport);
			}

			SgxIasReport& operator=(const sgx_ias_report_t& cRpt)
			{
				static_cast<sgx_ias_report_t&>(*this) = cRpt;

				return *this;
			}
		};

		struct RaSession
		{
			General128BitKey m_secretKey;
			SgxIasReport m_iasReport;

			static constexpr size_t GetSize()
			{
				return GENERAL_128BIT_16BYTE_SIZE + sizeof(m_iasReport.m_iasReport);
			}

			void ToBinary(std::vector<uint8_t>::iterator start, std::vector<uint8_t>::iterator end) const
			{
				if (std::distance(start, end) < static_cast<int64_t>(GetSize()))
				{
					throw RuntimeException("Failed to serialize SGX RA session, because buffer size is too small.");
				}

				auto keyEnd = std::copy(m_secretKey.begin(), m_secretKey.end(), start);

				std::copy(std::begin(m_iasReport.m_iasReport), std::end(m_iasReport.m_iasReport), keyEnd);
			}
		};

		struct RaClientSession
		{
			std::vector<uint8_t> m_ticket;
			RaSession m_session;
		};
	}
}
