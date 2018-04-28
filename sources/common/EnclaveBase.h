#pragma once
class EnclaveBase
{
public:
	EnclaveBase();
	~EnclaveBase();

	virtual bool Launch() = 0;

	virtual bool IsLastExecutionFailed() const = 0;

	virtual bool IsLaunched() const = 0;
};

