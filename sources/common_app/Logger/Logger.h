#pragma once

#include <queue>
#include <string>
#include <chrono>

struct LogMessagePiece;

//Not thread safe
class DecentLogger
{
public:
	DecentLogger() = delete;
	DecentLogger(const std::string& id);
	DecentLogger(const DecentLogger&) = delete;
	DecentLogger(DecentLogger&& other);
	~DecentLogger();

	void AddMessage(const char type, const std::string& msg);

	std::queue<LogMessagePiece*>& GetMsgQueue();

	std::string ToCsvLines();

private:
	const std::string m_id;
	std::queue<LogMessagePiece*> m_msgQueue;
};
