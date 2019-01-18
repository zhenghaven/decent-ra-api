#include <cstdio>
#include <cstring>

#include <string>
#include <iostream>

#include <tclap/CmdLine.h>
#include <boost/asio/ip/address_v4.hpp>
#include <json/json.h>

#include <sgx_tcrypto.h>

#include "../common_app/SGX/EnclaveUtil.h"
#include "../common_app/Common.h"

#include "../common_app/Net/LocalConnection.h"
#include "../common_app/Net/TCPConnection.h"
#include "../common_app/Net/TCPServer.h"
#include "../common_app/Net/SmartServer.h"

#include "../common_app/Ra/WhiteList/Requester.h"

#include "DecentVoteApp.h"

using namespace Decent;
using namespace Decent::Tools;

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
	sgx_status_t deviceStatusResErr = Sgx::GetDeviceStatus(deviceStatusRes);
	ASSERT(deviceStatusResErr == SGX_SUCCESS, "%s\n", Sgx::GetErrorMessage(deviceStatusResErr).c_str());

	uint32_t hostIP = boost::asio::ip::address_v4::from_string("127.0.0.1").to_uint();
	uint16_t hostPort = 57755U;

	std::cout << "================ This is App side ================" << std::endl;

	std::unique_ptr<Net::Connection> connection = std::make_unique<Net::TCPConnection>(hostIP, hostPort);
	//std::unique_ptr<Connection> connection(LocalConnection::Connect("TestLocalConnection"));

	Ra::WhiteList::Requester::Get().SendRequest(*connection); //Send WhiteList request.

	connection = std::make_unique<Net::TCPConnection>(hostIP, hostPort);

	std::shared_ptr<DecentVoteApp> enclave(
		std::make_shared<DecentVoteApp>(
			ENCLAVE_FILENAME, KnownFolderType::LocalAppDataEnclave, TOKEN_FILENAME, "TestHashList_01", *connection));

	//DecentAppLASession::SendHandshakeMessage(*connection, *enclave);
	//Json::Value jsonRoot;
	//connection->ReceivePack(jsonRoot);
	//enclave->ProcessSmartMessage(Messages::ParseCat(jsonRoot), jsonRoot, *connection);
	//
	//std::unique_ptr<Server> server(std::make_unique<TCPServer>(hostIP, hostPort + 5));

	//DecentSmartServer smartServer;
	//smartServer.AddServer(server, enclave);
	//smartServer.RunUtilUserTerminate();

	printf("Enter a character before exit ...\n");
	getchar();
	return 0;
}
