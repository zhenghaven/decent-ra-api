#pragma once

#include "../ServiceProviderBase.h"

class SGXServiceProviderBase : virtual public ServiceProviderBase
{
public:
	//static constexpr char const sk_platformType[] = "SGX";

public:
	using ServiceProviderBase::ServiceProviderBase;
	virtual ~SGXServiceProviderBase() {}

	virtual const char* GetPlatformType() const override { return "SGX"; }
};
