//#pragma once
//
//#include "SecureCommLayer.h"
//
//typedef struct ssl_st SSL;
//typedef struct bio_st BIO;
//
//class TLSCommLayer : public SecureCommLayer
//{
//public:
//	TLSCommLayer() = delete;
//	TLSCommLayer(SSL* ssl, bool isServer);
//	TLSCommLayer(const TLSCommLayer& other) = delete;
//	TLSCommLayer(TLSCommLayer&& other);
//
//	virtual ~TLSCommLayer();
//
//	TLSCommLayer& operator=(const TLSCommLayer& other) = delete;
//	TLSCommLayer& operator=(TLSCommLayer&& other);
//
//	operator bool() const;
//
//	virtual bool DecryptMsg(std::string& outMsg, const char* inMsg) const override;
//	virtual bool DecryptMsg(std::string& outMsg, const std::string& inMsg) const override;
//
//	virtual bool EncryptMsg(std::string& outMsg, const std::string& inMsg) const override;
//	virtual bool SendMsg(void* const connectionPtr, const std::string& msg, const char* appAttach) const override;
//
//private:
//	SSL * m_ssl;
//	BIO* m_inBuf;
//	BIO* m_outBuf;
//	bool m_isServer;
//	bool m_hasHandshaked;
//
//	void Clean();
//};
