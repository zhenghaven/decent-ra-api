#include <cstdio>
#include <cstring>

#include <string>
#include <iostream>

#include <sgx_urts.h>
#include <sgx_uae_service.h>

#include <tclap/CmdLine.h>

#include "../common_app/EnclaveUtil.h"
#include "../common_app/Common.h"
#include "ExampleEnclave.h"

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
	TCLAP::CmdLine cmd("Enclave Remote Attestation", ' ', "ver", true);

	//TCLAP::ValueArg<std::string> ipAddr("ip", "ipAddr", "IP Address", false, "127.0.0.1", "IP Address");

	//TCLAP::SwitchArg doesRunAsServer("s", "server", "Run as server", false);

	//cmd.add(ipAddr);
	//cmd.add(doesRunAsServer);

	//cmd.parse(argc, argv);

	sgx_device_status_t deviceStatusRes;
	sgx_status_t deviceStatusResErr = GetSGXDeviceStatus(deviceStatusRes);
	ASSERT(deviceStatusResErr == SGX_SUCCESS, GetSGXErrorMessage(deviceStatusResErr).c_str());

	ExampleEnclave exp(ENCLAVE_FILENAME, KnownFolderType::LocalAppDataEnclave, TOKEN_FILENAME);
	exp.Launch();
	exp.TestEnclaveFunctions();

	printf("Info: Cxx11DemoEnclave successfully returned.\n");

	printf("Enter a character before exit ...\n");

	std::cout << "================ Test Process Completed ================" << std::endl;

#ifdef RA_SERVER_SIDE
	std::cout << "================ This is server side ================" << std::endl;

#else
	std::cout << "================ This is client side ================" << std::endl;

#endif // RA_SERVER_SIDE


	getchar();
	return 0;
}
