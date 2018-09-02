#include <cstdio>
#include <cstring>

#include <string>
#include <iostream>

#include <tclap/CmdLine.h>
#include <boost/asio/ip/address_v4.hpp>
#include <json/json.h>

#include <sgx_tcrypto.h>

#include "../common_app/EnclaveUtil.h"
#include "../common_app/Common.h"
#include "../common_app/SGX/SGXDecentAppEnclave.h"
#include "../common_app/DecentAppLASession.h"
#include "../common_app/Messages.h"

#include "../common_app/Networking/LocalConnection.h"

/**
 * \brief	Main entry-point for this application
 *
 * \param	argc	The number of command-line arguments provided.
 * \param	argv	An array of command-line argument strings.
 *
 * \return	Exit-code for the process - 0 for success, else an error code.
 */
int main(int argc, char ** argv)
{
	TCLAP::CmdLine cmd("Enclave Remote Attestation", ' ', "ver", true);

	//TCLAP::ValueArg<std::string> ipAddr("ip", "ipAddr", "IP Address", false, "127.0.0.1", "IP Address");

	//TCLAP::SwitchArg doesRunAsServer("s", "server", "Run as server", false);

	TCLAP::ValueArg<int> testOpt("t", "test-opt", "Test Option Number", false, 0, "A single digit number.");

	cmd.add(testOpt);
	//cmd.add(doesRunAsServer);

	cmd.parse(argc, argv);

	sgx_device_status_t deviceStatusRes;
	sgx_status_t deviceStatusResErr = GetSGXDeviceStatus(deviceStatusRes);
	ASSERT(deviceStatusResErr == SGX_SUCCESS, "%s\n", GetSGXErrorMessage(deviceStatusResErr).c_str());

	uint32_t hostIP = boost::asio::ip::address_v4::from_string("127.0.0.1").to_uint();
	uint16_t hostPort = 57755U;

	std::cout << "================ This is App side ================" << std::endl;

	SGXDecentAppEnclave enclave(ENCLAVE_FILENAME, KnownFolderType::LocalAppDataEnclave, TOKEN_FILENAME);

	std::unique_ptr<Connection> connection(LocalConnection::Connect("TestLocalConnection"));
	DecentAppLASession::SendHandshakeMessage(connection, enclave);
	Json::Value jsonRoot;
	connection->Receive(jsonRoot);
	enclave.ProcessSmartMessage(Messages::ParseCat(jsonRoot), jsonRoot, connection);

	printf("Enter a character before exit ...\n");
	getchar();
	return 0;
}
