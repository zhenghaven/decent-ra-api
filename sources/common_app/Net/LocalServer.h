#include "Server.h"

#include <string>
#include <utility>
#include <memory>
#include <atomic>

namespace boost
{
	namespace interprocess
	{
		class shared_memory_object;
		class mapped_region;
	};
};

namespace Decent
{
	namespace Net
	{
		template<typename T>
		class SharedObject;

		struct LocalConnectStruct;
		struct LocalSessionStruct;
		struct LocalMessageQueue;

		class LocalAcceptor
		{
		public:
			LocalAcceptor() = delete;
			LocalAcceptor(const std::string& serverName);
			LocalAcceptor(const LocalAcceptor& other) = delete; //Copy is not allowed.
			LocalAcceptor(LocalAcceptor&& other);
			virtual ~LocalAcceptor() noexcept;

			LocalAcceptor& operator=(const LocalAcceptor& other) = delete;
			LocalAcceptor& operator=(LocalAcceptor&& other);

			bool IsTerminate() const noexcept;

			std::pair<
				std::pair<SharedObject<LocalSessionStruct>*, LocalMessageQueue*>,
				std::pair<SharedObject<LocalSessionStruct>*, LocalMessageQueue*> > Accept();

			void Terminate() noexcept;

		private:
			std::shared_ptr<SharedObject<LocalConnectStruct> > m_sharedObj;

			std::atomic<uint8_t> m_isTerminated;
		};

		class LocalServer : virtual public Server
		{
		public:
			LocalServer() = delete;
			LocalServer(const std::string& serverName);
			LocalServer(const LocalServer& other) = delete; //Copy is not allowed.
			LocalServer(LocalServer&& other);
			virtual ~LocalServer() noexcept;

			LocalServer& operator=(const LocalServer& other) = delete;
			LocalServer& operator=(LocalServer&& other);

			virtual std::unique_ptr<Connection> AcceptConnection() noexcept override;

			virtual bool IsTerminated() noexcept override;
			virtual void Terminate() noexcept override;

		private:
			LocalAcceptor m_acceptor;

			std::atomic<uint8_t> m_isTerminated;
		};
	}
}
