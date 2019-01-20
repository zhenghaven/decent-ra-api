#pragma once

#include <cstdint>

namespace Decent
{
	struct TimeStamp
	{
		uint16_t m_year;
		uint8_t  m_month;
		uint8_t  m_day;

		uint8_t  m_hour;
		uint8_t  m_min;
		uint8_t  m_sec;
		uint32_t m_nanoSec;
	};
}
