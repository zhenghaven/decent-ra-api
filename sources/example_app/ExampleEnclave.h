#pragma once

#include "../common/SGXEnclave.h"

class ExampleEnclave : public SGXEnclave
{
public:
	using SGXEnclave::SGXEnclave;

	void TestEnclaveFunctions();

private:

};
