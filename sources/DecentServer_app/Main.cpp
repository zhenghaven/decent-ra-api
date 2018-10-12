#include <cstdio>
#include <cstring>

#include <string>
#include <memory>
#include <iostream>

#include <tclap/CmdLine.h>
#include <boost/asio/ip/address_v4.hpp>
#include <json/json.h>

#include <sgx_tcrypto.h>

#include "../common/DataCoding.h"
#include "../common/OpenSSLTools.h"
#include "../common/SGX/SGXOpenSSLConversions.h"

#include "../common_app/SGX/SGXEnclaveUtil.h"
#include "../common_app/Common.h"
#include "../common_app/Messages.h"
#include "../common_app/DecentRASession.h"
#include "../common_app/SGX/SGXLASession.h"

#include "../common_app/Networking/TCPConnection.h"
#include "../common_app/Networking/TCPServer.h"
#include "../common_app/Networking/LocalConnection.h"
#include "../common_app/Networking/LocalServer.h"
#include "../common_app/Networking/DecentSmartServer.h"

#include "../common_app/Logger/LoggerManager.h"

#include "../common_app/SGX/IAS/IASConnector.h"

#include "ExampleEnclave.h"
#include "SimpleMessage.h"

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

	std::shared_ptr<IASConnector> iasConnector = std::make_shared<IASConnector>();

	uint32_t hostIP = boost::asio::ip::address_v4::from_string("128.114.52.211").to_uint();
	uint16_t hostPort = 57755U;

	std::cout << "================ This is server side ================" << std::endl;

	DecentSmartServer smartServer;

	switch (testOpt.getValue())
	{
	case 0:
	{
		std::shared_ptr<SGXDecentEnclave> enclave(
			std::make_shared<SGXDecentEnclave>(
				g_sgxSPID, iasConnector, true, ENCLAVE_FILENAME, KnownFolderType::LocalAppDataEnclave, TOKEN_FILENAME));
		
		//std::string decentSelfRaReport = expEnc.GetDecentSelfRAReport();
		//expEnc.ProcessDecentSelfRAReport(decentSelfRaReport);

		std::unique_ptr<Server> server(std::make_unique<TCPServer>(hostIP, hostPort));
		std::unique_ptr<Server> localServer(std::make_unique<LocalServer>("TestLocalConnection"));

		smartServer.AddServer(server, enclave);
		smartServer.AddServer(localServer, enclave);
		smartServer.RunUtilUserTerminate();

	}
	break;
	case 1:
	{
		ExampleEnclave expEnc(g_sgxSPID, iasConnector, false, ENCLAVE_FILENAME, KnownFolderType::LocalAppDataEnclave, TOKEN_FILENAME);

		std::unique_ptr<Connection> connection = std::make_unique<TCPConnection>(hostIP, hostPort);
		//std::unique_ptr<Connection> connection(LocalConnection::Connect("TestLocalConnection"));
		DecentRASession::SendHandshakeMessage(*connection, expEnc);
		Json::Value jsonRoot;
		connection->Receive(jsonRoot);
		expEnc.ProcessSmartMessage(Messages::ParseCat(jsonRoot), jsonRoot, *connection);
	}
	break;
	default:
		break;
	}

	printf("Enter a character before exit ...\n");
	getchar();
	return 0;
}