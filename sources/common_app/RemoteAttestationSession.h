#pragma once

#include <cstdint>
#include <functional>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/io_service.hpp>

class RAMessages;

class RemoteAttestationSession
{
public:
	typedef std::function<RAMessages*(const RAMessages*)> MsgProcessor;

public:
	RemoteAttestationSession() = delete;

	//Caution! Blocking constructors!
	RemoteAttestationSession(boost::asio::ip::tcp::acceptor& acceptor, size_t bufferSize = 5000U);
	RemoteAttestationSession(uint32_t ipAddr, uint16_t portNum, size_t bufferSize = 5000U);
	~RemoteAttestationSession();

	uint32_t GetIPv4Addr() const;
	uint16_t GetIPPort() const;

	///Connection ID is a combination of IPv4 and Port num.
	uint64_t GetConnectionID() const;

	virtual RAMessages* SendMessages(const RAMessages& msg) = 0;

	virtual bool RecvMessages(MsgProcessor msgProcessor) = 0;

protected:
	enum Mode
	{
		Server,
		Client,
	};
	Mode GetMode() const;

	boost::asio::io_service* m_ioService;
	boost::asio::ip::tcp::socket m_socket;

	std::string m_buffer;
};