//#include "TLSCommLayer.h"
//
//#include <openssl/bio.h>
//#include <openssl/ssl.h>
//
//TLSCommLayer & TLSCommLayer::operator=(TLSCommLayer && other)
//{
//	if (this != &other)
//	{
//		m_ssl = other.m_ssl;
//		m_inBuf = other.m_inBuf;
//		m_outBuf = other.m_outBuf;
//		m_isServer = other.m_isServer;
//		m_hasHandshaked = other.m_hasHandshaked;
//
//		other.m_ssl = nullptr;
//		other.m_inBuf = nullptr;
//		other.m_outBuf = nullptr;
//	}
//	return *this;
//}
//
//TLSCommLayer::operator bool() const
//{
//	return (m_ssl && m_inBuf && m_outBuf);
//}
//
//bool TLSCommLayer::DecryptMsg(std::string & outMsg, const char * inMsg) const
//{
//	return DecryptMsg(outMsg, inMsg);
//}
//
//bool TLSCommLayer::DecryptMsg(std::string & outMsg, const std::string & inMsg) const
//{
//	if (!*this || !m_hasHandshaked)
//	{
//		return false;
//	}
//
//	if (!BIO_write(m_inBuf, inMsg.data(), static_cast<int>(inMsg.size())))
//	{
//		return false;
//	}
//
//	outMsg.resize(SSL_pending(m_ssl));
//
//	return SSL_read(m_ssl, &outMsg[0], static_cast<int>(outMsg.size())) == outMsg.size();
//}
//
//bool TLSCommLayer::EncryptMsg(std::string & outMsg, const std::string & inMsg) const
//{
//	if (!*this || !m_hasHandshaked)
//	{
//		return false;
//	}
//
//	if (SSL_write(m_ssl, inMsg.data(), static_cast<int>(inMsg.size())) != inMsg.size())
//	{
//		return false;
//	}
//
//	outMsg.resize(BIO_ctrl_pending(m_outBuf));
//
//	return BIO_read(m_outBuf, &outMsg[0], static_cast<int>(outMsg.size())) == outMsg.size();
//}
//
//bool TLSCommLayer::SendMsg(void * const connectionPtr, const std::string & msg, const char * appAttach) const
//{
//	return false;
//}
//
//TLSCommLayer::TLSCommLayer(SSL * ssl, bool isServer) :
//	m_ssl(ssl),
//	m_inBuf(BIO_new(BIO_s_mem())),
//	m_outBuf(BIO_new(BIO_s_mem())),
//	m_isServer(isServer),
//	m_hasHandshaked(false)
//{
//	if (!*this)
//	{
//		Clean();
//		return;
//	}
//
//	BIO_set_mem_eof_return(m_inBuf, -1);
//	BIO_set_mem_eof_return(m_outBuf, -1);
//
//	SSL_set_bio(m_ssl, m_inBuf, m_outBuf);
//
//	if (isServer)
//	{
//		SSL_set_accept_state(m_ssl);
//	}
//	else
//	{
//		SSL_set_connect_state(m_ssl);
//	}
//}
//
//TLSCommLayer::TLSCommLayer(TLSCommLayer && other) :
//	m_ssl(other.m_ssl),
//	m_inBuf(other.m_inBuf),
//	m_outBuf(other.m_outBuf),
//	m_isServer(other.m_isServer),
//	m_hasHandshaked(other.m_hasHandshaked)
//{
//	other.m_ssl = nullptr;
//	other.m_inBuf = nullptr;
//	other.m_outBuf = nullptr;
//}
//
//TLSCommLayer::~TLSCommLayer()
//{
//	Clean();
//}
//
//void TLSCommLayer::Clean()
//{
//	SSL_free(m_ssl);
//	BIO_free_all(m_inBuf);
//	BIO_free_all(m_outBuf);
//
//	m_ssl = nullptr;
//	m_inBuf = nullptr;
//	m_outBuf = nullptr;
//}
