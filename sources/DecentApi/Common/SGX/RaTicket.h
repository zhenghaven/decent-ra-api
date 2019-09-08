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
			G128BitSecretKeyWrap m_secretKey;
			G128BitSecretKeyWrap m_maskingKey;
			SgxIasReport m_iasReport;

			RaSession() = default;

			~RaSession()
			{}

			RaSession(const RaSession& rhs) :
				m_secretKey(rhs.m_secretKey),
				m_maskingKey(rhs.m_maskingKey),
				m_iasReport(rhs.m_iasReport)
			{}

			RaSession(std::vector<uint8_t>::const_iterator start, std::vector<uint8_t>::const_iterator end) :
				RaSession()
			{
				ReadBinary(start, end);
			}

			static constexpr size_t GetSize()
			{
				return GENERAL_128BIT_16BYTE_SIZE + GENERAL_128BIT_16BYTE_SIZE + sizeof(m_iasReport.m_iasReport);
			}

			std::vector<uint8_t>::const_iterator ReadBinary(std::vector<uint8_t>::const_iterator start, std::vector<uint8_t>::const_iterator end)
			{
				if (std::distance(start, end) < static_cast<int64_t>(GetSize()))
				{
					throw RuntimeException("Failed to de-serialize SGX RA session, because the binary size is too small.");
				}

				auto prevStart = start;
				auto prevEnd = start + m_secretKey.m_key.size();
				std::copy(prevStart, prevEnd, m_secretKey.m_key.begin());

				prevStart = prevEnd;
				prevEnd = prevStart + m_maskingKey.m_key.size();
				std::copy(prevStart, prevEnd, m_maskingKey.m_key.begin());

				prevStart = prevEnd;
				prevEnd = prevStart + sizeof(m_iasReport.m_iasReport);
				std::copy(prevStart, prevEnd, std::begin(m_iasReport.m_iasReport));

				return prevEnd;
			}

			std::vector<uint8_t>::iterator ToBinary(std::vector<uint8_t>::iterator start, std::vector<uint8_t>::iterator end) const
			{
				if (std::distance(start, end) < static_cast<int64_t>(GetSize()))
				{
					throw RuntimeException("Failed to serialize SGX RA session, because the buffer size is too small.");
				}

				auto prevEnd = start;

				prevEnd = std::copy(m_secretKey.m_key.begin(), m_secretKey.m_key.end(), prevEnd);
				prevEnd = std::copy(m_maskingKey.m_key.begin(), m_maskingKey.m_key.end(), prevEnd);
				prevEnd = std::copy(std::begin(m_iasReport.m_iasReport), std::end(m_iasReport.m_iasReport), prevEnd);

				return prevEnd;
			}
		};

		struct RaClientSession
		{
			std::vector<uint8_t> m_ticket;
			RaSession m_session;
		};
	}
}
