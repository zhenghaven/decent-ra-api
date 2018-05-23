#pragma once

#include <cstdint>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/io_service.hpp>

class RemoteAttestationSession
{
public:
	RemoteAttestationSession() = delete;

	//Caution! Blocking constructors!
	RemoteAttestationSession(boost::asio::ip::tcp::acceptor& acceptor);
	RemoteAttestationSession(uint32_t ipAddr, uint16_t portNum);
	~RemoteAttestationSession();

	uint32_t GetIPv4Addr() const;
	uint16_t GetIPPort() const;

	///Connection ID is a combination of IPv4 and Port num.
	uint64_t GetConnectionID() const;

	virtual bool ProcessMessages() = 0;

protected:
	enum Mode
	{
		Server,
		Client,
	};
	Mode GetMode() const;

	boost::asio::io_service* m_ioService;
	boost::asio::ip::tcp::socket m_socket;
};