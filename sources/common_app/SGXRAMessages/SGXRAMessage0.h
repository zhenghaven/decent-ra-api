#pragma once

#include "SGXRAMessage.h"

class SGXRAMessage0 : public SGXRAMessage
{
public:
	SGXRAMessage0();
	~SGXRAMessage0();

	virtual std::vector<uint8_t> SerializedMessage() const override;

	virtual std::string ToJsonString() const override;

private:

};

SGXRAMessage0::SGXRAMessage0()
{
}

SGXRAMessage0::~SGXRAMessage0()
{
}

