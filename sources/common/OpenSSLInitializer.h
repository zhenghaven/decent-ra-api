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
