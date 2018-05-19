#pragma once

#include "../common_app/SGXEnclave.h"

class ExampleEnclave : public SGXEnclave
{
public:
	using SGXEnclave::SGXEnclave;

	void TestEnclaveFunctions();

private:

};
