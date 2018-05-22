#pragma once

#include <cstdint>

#include <boost/asio/ip/tcp.hpp>

class RemoteAttestationSession
{
public:
	RemoteAttestationSession() = delete;
	RemoteAttestationSession(boost::asio::ip::tcp::acceptor& acceptor);
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

	boost::asio::ip::tcp::socket m_socket;
};