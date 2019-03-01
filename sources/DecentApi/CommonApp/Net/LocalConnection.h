#include "Connection.h"

#include <memory>
#include <utility>

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

		class LocalAcceptor;
		struct LocalSessionStruct;
		struct LocalMessageQueue;

		struct LocalAcceptedResult;

		class LocalConnection : public Connection
		{
		public:
			static LocalConnection Connect(const std::string& serverName);

		public:
			LocalConnection() = delete;
			LocalConnection(LocalAcceptor& acceptor);
			LocalConnection(const LocalConnection& other) = delete;
			LocalConnection(LocalConnection&& other) noexcept;
			virtual ~LocalConnection() noexcept;

			LocalConnection& operator=(const LocalConnection& other) = delete;
			LocalConnection& operator=(LocalConnection&& other);

			virtual size_t SendRaw(const void* const dataPtr, const size_t size) override;

			virtual size_t ReceiveRaw(void* const bufPtr, const size_t size) override;

			virtual bool IsTerminate() const noexcept;

			virtual void Terminate() noexcept override;

		private:
			LocalConnection(const std::string& sessionId);
			LocalConnection(LocalAcceptedResult&& sharedObjs) noexcept;

		private:
			std::unique_ptr<SharedObject<LocalSessionStruct> > m_inSharedObj;
			std::unique_ptr<SharedObject<LocalSessionStruct> > m_outSharedObj;
			std::unique_ptr<LocalMessageQueue> m_inMsgQ;
			std::unique_ptr<LocalMessageQueue> m_outMsgQ;
		};
	}
}
