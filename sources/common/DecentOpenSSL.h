#pragma once

#include "OpenSSLTools.h"

class DecentServerX509 : public X509Wrapper
{
public:
	DecentServerX509() = delete;
	DecentServerX509(const std::string& pemStr);
	DecentServerX509(const ECKeyPair& prvKey, const std::string& enclaveHash, const std::string& platformType, const std::string& selfRaReport);
	DecentServerX509(const X509Wrapper& other) = delete;
	virtual ~DecentServerX509() {}

	const std::string& GetPlatformType() const;
	const std::string& GetSelfRaReport() const;

private:
	const std::string ParsePlatformType() const;
	const std::string ParseSelfRaReport() const;
	const std::string k_platformType;
	const std::string k_selfRaReport;
};

class DecentAppX509 : public X509Wrapper
{
public:
	DecentAppX509() = delete;
	DecentAppX509(const std::string& pemStr);
	DecentAppX509(const ECKeyPublic& pubKey, const DecentServerX509& caCert, const ECKeyPair& serverPrvKey, const std::string& enclaveHash, const std::string& platformType, const std::string& appId);
	DecentAppX509(const X509Wrapper& other) = delete;
	virtual ~DecentAppX509() {}

	const std::string& GetPlatformType() const;
	const std::string& GetAppId() const;

private:
	const std::string ParsePlatformType() const;
	const std::string ParseAppId() const;
	const std::string k_platformType;
	const std::string k_appId;
};
