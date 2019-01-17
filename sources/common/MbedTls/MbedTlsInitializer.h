#pragma once

class MbedTlsInitializer
{
public:
	static MbedTlsInitializer& GetInst();
	~MbedTlsInitializer();

private:
	MbedTlsInitializer();

};
