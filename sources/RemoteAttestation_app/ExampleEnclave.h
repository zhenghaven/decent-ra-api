#pragma once

#include "../common_app/SGXEnclave.h"

class ExampleEnclave : public SGXEnclave
{
public:
	using SGXEnclave::SGXEnclave;

	virtual sgx_status_t GetRAPublicKey(sgx_ec256_public_t& outKey) override;

	void TestEnclaveFunctions();

private:

};
