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

		struct LocalAcceptedResult
		{
			LocalAcceptedResult() noexcept;

			~LocalAcceptedResult();

			LocalAcceptedResult(std::unique_ptr<SharedObject<LocalSessionStruct> >& sharedObj_a,
				std::unique_ptr<LocalMessageQueue>& msgQ_a,
				std::unique_ptr<SharedObject<LocalSessionStruct> >& sharedObj_b,
				std::unique_ptr<LocalMessageQueue>& msgQ_b) noexcept;

			LocalAcceptedResult(const LocalAcceptedResult&) = delete;
			LocalAcceptedResult(LocalAcceptedResult&& rhs) noexcept;

			std::unique_ptr<SharedObject<LocalSessionStruct> > m_sharedObj_a;
			std::unique_ptr<LocalMessageQueue> m_msgQ_a;

			std::unique_ptr<SharedObject<LocalSessionStruct> > m_sharedObj_b;
			std::unique_ptr<LocalMessageQueue> m_msgQ_b;
		};

		/** \brief	Acceptor for local connection. */
		class LocalAcceptor
		{
		public:
			LocalAcceptor() = delete;

			/**
			 * \brief	Constructor
			 *
			 * \param	serverName	Name of the server.
			 */
			LocalAcceptor(const std::string& serverName) noexcept;
			LocalAcceptor(const LocalAcceptor& other) = delete; //Copy is not allowed.
			LocalAcceptor(LocalAcceptor&& other) noexcept;
			virtual ~LocalAcceptor() noexcept;

			LocalAcceptor& operator=(const LocalAcceptor& other) = delete;
			LocalAcceptor& operator=(LocalAcceptor&& other) noexcept;

			bool IsTerminate() const noexcept;

			LocalAcceptedResult Accept();

			void Terminate() noexcept;

		private:
			std::shared_ptr<SharedObject<LocalConnectStruct> > m_sharedObj;

			std::atomic_uint8_t m_isTerminated;
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

			virtual std::unique_ptr<Connection> AcceptConnection() override;

			virtual bool IsTerminated() noexcept override;
			virtual void Terminate() noexcept override;

		private:
			LocalAcceptor m_acceptor;

			std::atomic<uint8_t> m_isTerminated;
		};
	}
}
