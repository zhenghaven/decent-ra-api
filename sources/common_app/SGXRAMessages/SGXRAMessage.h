#pragma once

#include <vector>
#include <cstdint>

class SGXRAMessage
{
public:
	SGXRAMessage();
	~SGXRAMessage();

	virtual std::vector<uint8_t> SerializedMessage() const = 0;

	virtual std::string ToJsonString() const = 0;

private:

};