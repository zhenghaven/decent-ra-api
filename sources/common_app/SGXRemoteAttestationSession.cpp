#include "SGXRemoteAttestationSession.h"

#include "Common.h"

SGXRemoteAttestationSession::~SGXRemoteAttestationSession()
{
}

bool SGXRemoteAttestationSession::ProcessMessages()
{
	switch (RemoteAttestationSession::GetMode())
	{
	case RemoteAttestationSession::Mode::Client:
		return ProcessClientMessages();
	case RemoteAttestationSession::Mode::Server:
		return ProcessServerMessages();
	default:
		return false;
	}
}

bool SGXRemoteAttestationSession::ProcessServerMessages()
{
	std::string buffer;
	buffer.resize(1000, '\0');
	m_socket.receive(boost::asio::buffer(&buffer[0], 1000));
	LOGI("%s\n", buffer.c_str());
	m_socket.send(boost::asio::buffer(&buffer[0], buffer.size()));
	return true;
}

bool SGXRemoteAttestationSession::ProcessClientMessages()
{
	std::string buffer = "TEST MESSAGE";
	m_socket.send(boost::asio::buffer(&buffer[0], buffer.size()));
	buffer.resize(0);
	buffer.resize(1000, '\0');
	m_socket.receive(boost::asio::buffer(&buffer[0], 1000));
	LOGI("%s\n", buffer.c_str());
	return true;
}
