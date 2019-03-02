#include "LoggerManager.h"

#include <thread>
#include <chrono>
#include <iomanip>
#include <ctime>
#include <sstream>
#include <exception>

#include <boost/filesystem.hpp>

#include "../Tools/DiskFile.h"
#include "../../Common/Common.h"

using namespace Decent::Tools;
using namespace Decent::Logger;
namespace fs = boost::filesystem;

DecentLoggerManager & DecentLoggerManager::GetInstance()
{
	static DecentLoggerManager instance;
	return instance;
}

static fs::path ConstructFilePath()
{
	fs::path res(fs::current_path());

	std::time_t t = std::time(nullptr);
	std::tm tm = *std::localtime(&t);
	std::stringstream ss;
	ss << "DecentLog_" << std::put_time(&tm, "%Y%m%d_%H%M%S") << ".csv";

	res.append(ss.str());

	return res;
}

DecentLoggerManager::DecentLoggerManager(bool isCritical) :
	m_isCritical(isCritical),
	m_outFilePath(std::make_unique<fs::path>(ConstructFilePath())),
	m_isTerminated(false),
	m_logger(std::make_unique<DecentLogger>("DecentLoggerManager"))
{
	m_logger->AddMessage('I', "Logger Service Started.");

	m_writerThread = new std::thread([this]() 
	{
		std::queue<std::unique_ptr<DecentLogger> > loggerQueue;
		
		std::unique_lock<std::mutex> queueLock(m_queueMutex);
		while (!m_isTerminated || m_loggerQueue.size() > 0)
		{
			if (m_loggerQueue.size() > 0)
			{
				m_loggerQueue.swap(loggerQueue);
			}
			queueLock.unlock();

			while (loggerQueue.size() > 0)
			{
				try
				{
					WritableDiskFile file(*m_outFilePath, WritableFileBase::WritableMode::Append);
					LOGI("Writing log to file: %s\n", m_outFilePath->string().c_str());
					file.WriteBlock(loggerQueue.front()->ToCsvLines());
					loggerQueue.pop();
				}
				catch (const FileException& e)
				{
					LOGW("Cannot open log file: %s !\n", m_outFilePath->string().c_str());
					if (m_isCritical)
					{
						throw e;
					}
				}
			}

			if (!m_isTerminated) 
			{
				queueLock.lock();
				m_queueSignal.wait(queueLock);
			}
		}
	});
}

DecentLoggerManager::~DecentLoggerManager()
{
	m_logger->AddMessage('I', "Logger Service Stopped.");
	AddLogger(m_logger);

	m_isTerminated = true;

	m_queueSignal.notify_all();
	m_writerThread->join();
	delete m_writerThread;
}

void DecentLoggerManager::AddLogger(std::unique_ptr<DecentLogger>& logger)
{
	if (m_isTerminated)
	{
		return;
	}

	std::unique_lock<std::mutex> queueLock(m_queueMutex);

	m_loggerQueue.push(std::move(logger));
	m_queueSignal.notify_one();
}
