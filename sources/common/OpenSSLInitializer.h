#pragma once

class OpenSSLInitializer
{
public:
	//thread-safe since c++11.
	static const OpenSSLInitializer& Initialize();
	~OpenSSLInitializer();

private:
	OpenSSLInitializer();

};

class DecentOpenSSLInitializer
{
public:
	//thread-safe since c++11.
	static const DecentOpenSSLInitializer& Initialize();
	~DecentOpenSSLInitializer();

	//OpenSSLInitializer& GetOpenSSLInitializer();
	const OpenSSLInitializer& GetOpenSSLInitializer() const;

	int GetSelfRAReportNID() const;
	int GetLocalAttestationIdNID() const;
	int GetPlatformTypeNID() const;

private:
	DecentOpenSSLInitializer();

	const OpenSSLInitializer& k_baseInit;
	const int k_selfRAReportNID;
	const int k_laIdNID;
	const int k_platformTypeNID;
};
