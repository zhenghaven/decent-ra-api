#pragma once

#include <memory>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <atomic>

#include "Logger.h"

//class DecentLogger;

namespace std
{
	class thread;
}
namespace boost
{
	namespace filesystem
	{
		class path;
	}
}

//thread safe
class DecentLoggerManager
{
public:
	static DecentLoggerManager& GetInstance();

public:
	DecentLoggerManager(bool isCritical = true);
	~DecentLoggerManager();

	void AddLogger(std::unique_ptr<DecentLogger>& logger);

private:
	const bool m_isCritical;
	const std::unique_ptr<const boost::filesystem::path> m_outFilePath;
	std::mutex m_queueMutex;
	std::condition_variable m_queueSignal;
	std::queue<std::unique_ptr<DecentLogger> > m_loggerQueue;

	std::unique_ptr<DecentLogger> m_logger;
	std::thread* m_writerThread;
	std::atomic<bool> m_isTerminated;
};
