#include <cstdio>
#include <cstring>

#include <string>
#include <iostream>

#include <tclap/CmdLine.h>
#include <boost/asio/ip/address_v4.hpp>
#include <json/json.h>

#include "../common_app/EnclaveUtil.h"
#include "../common_app/Common.h"

#include "../common_app/Networking/Connection.h"

#include "ExampleEnclave.h"
#include "SimpleMessage.h"
#include "../common_app/RAMessageRevRAReq.h"

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
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
	ASSERT(deviceStatusResErr == SGX_SUCCESS, GetSGXErrorMessage(deviceStatusResErr).c_str());

	ExampleEnclave exp(ENCLAVE_FILENAME, KnownFolderType::LocalAppDataEnclave, TOKEN_FILENAME);
	exp.Launch();
	//exp.InitRAEnvironment();

	std::cout << "================ Test Process Completed ================" << std::endl;

	uint32_t hostIP = boost::asio::ip::address_v4::from_string("127.0.0.1").to_uint();
	uint16_t hostPort = 57755U;

	Json::Value jsonRoot;
	Json::CharReaderBuilder rbuilder;
	rbuilder["collectComments"] = false;
	std::string errStr;

	const std::unique_ptr<Json::CharReader> reader(rbuilder.newCharReader());

#ifdef RA_SERVER_SIDE
	std::cout << "================ This is server side ================" << std::endl;

	switch (testOpt.getValue())
	{
	case 0:
	{
		exp.SetDecentMode(DecentNodeMode::ROOT_SERVER);
		exp.LaunchRAServer(hostIP, hostPort);
		if (!exp.IsRAServerLaunched())
		{
			LOGE("RA Server Launch Failed!");
		}
		std::unique_ptr<Connection> connection = exp.AcceptRAConnection();
		std::unique_ptr<Connection> connection2 = exp.AcceptRAConnection();
	}
		
		break;
	case 1:
	{
		exp.SetDecentMode(DecentNodeMode::ROOT_SERVER);
		std::unique_ptr<Connection> connection = exp.RequestRA(hostIP, hostPort);

		exp.LaunchRAServer(hostIP, 57756U);
		std::unique_ptr<Connection> connection2 = exp.AcceptRAConnection();
	}
	break;
	case 2:
	{
		exp.SetDecentMode(DecentNodeMode::APPL_SERVER);
		std::unique_ptr<Connection> connection = exp.RequestRA(hostIP, 57756U);

		exp.LaunchRAServer(hostIP, 57750U);
		std::unique_ptr<Connection> connection2 = exp.AcceptRAConnection();

		std::string buffer;
		connection2->Receive(buffer);
		reader->parse(buffer.c_str(), buffer.c_str() + buffer.size(), &jsonRoot, &errStr);

		RAMessageRevRAReq revMsg(jsonRoot);
		uint64_t secret;
		sgx_aes_gcm_128bit_tag_t secretMac;
		exp.GetSimpleSecret(revMsg.GetSenderID(), secret, secretMac);
		SimpleMessage sMsg(exp.GetRASenderID(), secret, secretMac);
		connection2->Send(sMsg.ToJsonString());
	}
	break;
	case 3:
	{
		exp.SetDecentMode(DecentNodeMode::APPL_SERVER);
		std::unique_ptr<Connection> connection = exp.RequestRA(hostIP, hostPort);

		std::unique_ptr<Connection> connection2 = exp.RequestAppNodeConnection(hostIP, 57750U);
		RAMessageRevRAReq revMsg(exp.GetRASenderID());
		connection2->Send(revMsg.ToJsonString());

		std::string buffer;
		connection2->Receive(buffer);
		reader->parse(buffer.c_str(), buffer.c_str() + buffer.size(), &jsonRoot, &errStr);

		SimpleMessage sMsg(jsonRoot);
		exp.ProcessSimpleSecret(sMsg.GetSenderID(), sMsg.GetSecret(), sMsg.GetSecretMac());

	}
	break;
	default:
		break;
	}

#else
	std::cout << "================ This is client side ================" << std::endl;

	exp.SetDecentMode(DecentNodeMode::ROOT_SERVER);
	std::unique_ptr<Connection> connection(exp.RequestRA(hostIP, hostPort));

#endif // RA_SERVER_SIDE

	printf("Enter a character before exit ...\n");
	getchar();
	return 0;
}
