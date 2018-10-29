#include <cstdio>
#include <cstring>

#include <string>
#include <memory>
#include <iostream>

#include <tclap/CmdLine.h>
#include <boost/asio/ip/address_v4.hpp>
#include <json/json.h>

#include "../common_app/SGX/SGXEnclaveUtil.h"
#include "../common_app/Common.h"
#include "../common_app/Messages.h"
#include "../common_app/DecentRASession.h"

#include "../common_app/Networking/TCPConnection.h"
#include "../common_app/Networking/TCPServer.h"
#include "../common_app/Networking/LocalConnection.h"
#include "../common_app/Networking/LocalServer.h"
#include "../common_app/Networking/DecentSmartServer.h"

#include "../common_app/SGX/IasConnector.h"

#include "ExampleEnclave.h"

static sgx_spid_t g_sgxSPID = { {
		0xDD,
		0x16,
		0x40,
		0xFE,
		0x0D,
		0x28,
		0xC9,
		0xA8,
		0xB3,
		0x05,
		0xAF,
		0x4D,
		0x4E,
		0x76,
		0x58,
		0xBE,
	} };

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
	TCLAP::CmdLine cmd("Decent Remote Attestation", ' ', "ver", true);

#ifndef DEBUG
	TCLAP::SwitchArg argIsRoot("r", "root", "Start as root server", false);
	cmd.add(argIsRoot);
	TCLAP::ValueArg<std::string> argRootAddr("a", "root-addr", "IP Address for root server", false, "127.0.0.1", "IP Addr");
	cmd.add(argRootAddr);
	TCLAP::ValueArg<uint16_t>  argRootPort("b", "root-port", "TCP port for root server", false, 0, "TCP Port Num");
	cmd.add(argRootPort);
	TCLAP::ValueArg<std::string> argServerAddr("c", "server-addr", "IP Address for this server", true, "127.0.0.1", "IP Addr");
	cmd.add(argServerAddr);
	TCLAP::ValueArg<uint16_t>  argServerPort("d", "server-port", "TCP port for this server", true, 0, "TCP Port Num");
	cmd.add(argServerPort);
	TCLAP::ValueArg<uint16_t>  argLocalPort("l", "local-port", "Port number (local connection) for this server", true, 0, "Port Num");
	cmd.add(argLocalPort);
#else
	TCLAP::ValueArg<int> testOpt("t", "test-opt", "Test Option Number", false, 0, "A single digit number.");
	cmd.add(testOpt);
#endif

	cmd.parse(argc, argv);

#ifndef DEBUG
	bool isRootServer = argIsRoot.getValue();
	std::string rootServerAddr = argRootAddr.getValue();
	uint16_t rootServerPort = argRootPort.getValue();
	std::string serverAddr = argServerAddr.getValue();
	uint16_t serverPort = argServerPort.getValue();
	std::string localAddr = "DecentServerLocal";
	uint16_t localPort = argLocalPort.getValue();
#else
	bool isRootServer = testOpt.getValue() == 0 ? true :  false;
	std::string rootServerAddr = "127.0.0.1";
	uint16_t rootServerPort = 57755U;
	std::string serverAddr = rootServerAddr;
	uint16_t serverPort = isRootServer ? rootServerPort : rootServerPort + 1;
	std::string localAddr = "DecentServerLocal";
	uint16_t localPort = serverPort;
#endif

	uint32_t rootServerIp = boost::asio::ip::address_v4::from_string(rootServerAddr).to_uint();
	uint32_t serverIp = boost::asio::ip::address_v4::from_string(serverAddr).to_uint();


	sgx_device_status_t deviceStatusRes;
	sgx_status_t deviceStatusResErr = GetSGXDeviceStatus(deviceStatusRes);
	ASSERT(deviceStatusResErr == SGX_SUCCESS, "%s\n", GetSGXErrorMessage(deviceStatusResErr).c_str());

	std::shared_ptr<IASConnector> iasConnector = std::make_shared<IASConnector>();
	DecentSmartServer smartServer;

	std::cout << "================ Decent Server ================" << std::endl;

	std::shared_ptr<SGXDecentEnclave> enclave(
		std::make_shared<SGXDecentEnclave>(
			g_sgxSPID, iasConnector, isRootServer, ENCLAVE_FILENAME, KnownFolderType::LocalAppDataEnclave, TOKEN_FILENAME));

	if (!isRootServer)
	{
		std::unique_ptr<Connection> connection = std::make_unique<TCPConnection>(rootServerIp, rootServerPort);
		DecentRASession::SendHandshakeMessage(*connection, *enclave);
		Json::Value jsonRoot;
		connection->ReceivePack(jsonRoot);
		enclave->ProcessSmartMessage(Messages::ParseCat(jsonRoot), jsonRoot, *connection);
	}

	std::unique_ptr<Server> server(std::make_unique<TCPServer>(serverIp, serverPort));
	std::unique_ptr<Server> localServer(std::make_unique<LocalServer>(localAddr + std::to_string(localPort)));

	smartServer.AddServer(server, enclave);
	smartServer.AddServer(localServer, enclave);
	smartServer.RunUtilUserTerminate();

	printf("Exit ...\n");
	return 0;
}
