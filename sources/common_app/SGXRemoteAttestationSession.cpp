#include "SGXRemoteAttestationSession.h"

#include <cstring>

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
	m_socket.receive(boost::asio::buffer(&m_buffer[0], m_buffer.size()));
	LOGI("%s\n", m_buffer.c_str());
	m_socket.send(boost::asio::buffer(&m_buffer[0], std::strlen(m_buffer.c_str())));
	return true;
}

bool SGXRemoteAttestationSession::ProcessClientMessages()
{
	std::string msg = "TEST MESSAGE";
	memcpy(&m_buffer[0], &msg[0], msg.size());
	m_socket.send(boost::asio::buffer(&m_buffer[0], std::strlen(m_buffer.c_str())));
	m_socket.receive(boost::asio::buffer(&m_buffer[0], m_buffer.size()));
	LOGI("%s\n", m_buffer.c_str());
	LOGI("buffer size: %d\n", m_buffer.size());
	return true;
}
