#include <cstdio>
#include <cstring>

#include <string>

#include <sgx_urts.h>
#include <sgx_uae_service.h>

#ifdef _MSC_VER
# include <Shlobj.h>
#else
# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX
# define FALSE 0
#endif

#include "../common_app/EnclaveUtil.h"
#include "../common_app/Common.h"
#include "ExampleEnclave.h"

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
	(void)(argc);
	(void)(argv);
	
	sgx_device_status_t deviceStatusRes;
	sgx_status_t deviceStatusResErr = GetSGXDeviceStatus(deviceStatusRes);
	ASSERT(deviceStatusResErr == SGX_SUCCESS, GetSGXErrorMessage(deviceStatusResErr).c_str());

	ExampleEnclave exp(ENCLAVE_FILENAME, KnownFolderType::LocalAppDataEnclave, TOKEN_FILENAME);
	exp.Launch();
	exp.TestEnclaveFunctions();

	printf("Info: Cxx11DemoEnclave successfully returned.\n");

	printf("Enter a character before exit ...\n");
	getchar();
	return 0;
}
