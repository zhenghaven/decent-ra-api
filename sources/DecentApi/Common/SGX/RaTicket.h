#pragma once

#include <vector>

#include <mbedTLScpp/SKey.hpp>
#include <mbedTLScpp/SecretVector.hpp>

#include "../Exceptions.h"
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
			mbedTLScpp::SKey<128> m_secretKey;
			mbedTLScpp::SKey<128> m_maskingKey;
			SgxIasReport m_iasReport;

			RaSession() = default;

			~RaSession()
			{}

			RaSession(const RaSession& rhs) :
				m_secretKey(rhs.m_secretKey),
				m_maskingKey(rhs.m_maskingKey),
				m_iasReport(rhs.m_iasReport)
			{}

			RaSession(mbedTLScpp::SecretVector<uint8_t>::const_iterator start, mbedTLScpp::SecretVector<uint8_t>::const_iterator end) :
				RaSession()
			{
				ReadBinary(start, end);
			}

			static constexpr size_t GetSize()
			{
				return decltype(m_secretKey)::sk_itemCount +
					decltype(m_secretKey)::sk_itemCount +
					sizeof(m_iasReport.m_iasReport);
			}

			template<typename _IteratorType>
			_IteratorType ReadBinary(_IteratorType start, _IteratorType end)
			{
				if (std::distance(start, end) < static_cast<int64_t>(GetSize()))
				{
					throw RuntimeException("Failed to de-serialize SGX RA session, because the binary size is too small.");
				}

				auto prevStart = start;
				auto prevEnd = start + m_secretKey.size();
				std::copy(prevStart, prevEnd, m_secretKey.begin());

				prevStart = prevEnd;
				prevEnd = prevStart + m_maskingKey.size();
				std::copy(prevStart, prevEnd, m_maskingKey.begin());

				prevStart = prevEnd;
				prevEnd = prevStart + sizeof(m_iasReport.m_iasReport);
				std::copy(prevStart, prevEnd, std::begin(m_iasReport.m_iasReport));

				return prevEnd;
			}

			template<typename _IteratorType>
			_IteratorType ToBinary(_IteratorType start, _IteratorType end) const
			{
				if (std::distance(start, end) < static_cast<int64_t>(GetSize()))
				{
					throw RuntimeException("Failed to serialize SGX RA session, because the buffer size is too small.");
				}

				auto prevEnd = start;

				prevEnd = std::copy(m_secretKey.begin(), m_secretKey.end(), prevEnd);
				prevEnd = std::copy(m_maskingKey.begin(), m_maskingKey.end(), prevEnd);
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
