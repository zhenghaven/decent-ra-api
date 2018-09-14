#include "Logger.h"

#include <sstream>
#include <chrono>

struct LogMessagePiece
{
	const std::chrono::high_resolution_clock::time_point m_timestamp;
	const char m_type;
	const std::string m_msg;

	LogMessagePiece() = delete;
	LogMessagePiece(const char type, const std::string& msg) :
		m_timestamp(std::chrono::high_resolution_clock::now()),
		m_type(type),
		m_msg(msg)
	{
	}

};

DecentLogger::DecentLogger(const std::string & id) :
	m_id(id)
{
}

DecentLogger::DecentLogger(DecentLogger && other) :
	m_msgQueue(std::move(other.m_msgQueue))
{
}

DecentLogger::~DecentLogger()
{
	while (m_msgQueue.size() > 0)
	{
		delete m_msgQueue.front();
		m_msgQueue.pop();
	}
}

void DecentLogger::AddMessage(const char type, const std::string & msg)
{
	m_msgQueue.push(new LogMessagePiece(type, msg));
}

std::queue<LogMessagePiece*>& DecentLogger::GetMsgQueue()
{
	return m_msgQueue;
}

std::string DecentLogger::ToCsvLines()
{
	std::stringstream ss;

	std::chrono::high_resolution_clock::time_point tp;
	if (m_msgQueue.size() > 0)
	{
		tp = m_msgQueue.front()->m_timestamp;
	}

	while (m_msgQueue.size() > 0)
	{
		LogMessagePiece& item = *m_msgQueue.front();
		ss << "\"" << m_id << "\", " << item.m_type << ", " << item.m_timestamp.time_since_epoch().count() << ", " << (item.m_timestamp - tp).count() << ", \"" << item.m_msg << "\"" << std::endl;
		tp = item.m_timestamp;
		delete m_msgQueue.front();
		m_msgQueue.pop();
	}
	
	return ss.str();
}
