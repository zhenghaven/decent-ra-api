#include <cstdio>
#include <cstring>

#include <string>
#include <iostream>

#include <tclap/CmdLine.h>
#include <boost/asio/ip/address_v4.hpp>
#include <json/json.h>

#include "../common_app/EnclaveUtil.h"
#include "../common_app/Common.h"
#include "../common_app/DecentRASession.h"

#include "../common_app/Networking/Connection.h"
#include "../common_app/Networking/Server.h"

#include "../common_app/SGX/IAS/IASConnector.h"

#include "ExampleEnclave.h"
#include "SimpleMessage.h"
#include "../common_app/RAMessageRevRAReq.h"

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
	ASSERT(deviceStatusResErr == SGX_SUCCESS, GetSGXErrorMessage(deviceStatusResErr).c_str());

	IASConnector iasConnector;
	ExampleEnclave expEnc(ENCLAVE_FILENAME, iasConnector, KnownFolderType::LocalAppDataEnclave, TOKEN_FILENAME);
	expEnc.Launch();
	//expEnc.InitRAEnvironment();

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
		expEnc.SetDecentMode(DecentNodeMode::ROOT_SERVER);
		Server ser(hostIP, hostPort);

		std::unique_ptr<Connection> connection = ser.AcceptConnection();
		DecentRASession decentRA(connection, expEnc, expEnc);
		decentRA.ProcessServerSideRA();

		std::unique_ptr<Connection> connection2 = ser.AcceptConnection();
		DecentRASession decentRA2(connection2, expEnc, expEnc);
		decentRA2.ProcessServerSideRA();
	}
	break;
	case 1:
	{
		expEnc.SetDecentMode(DecentNodeMode::ROOT_SERVER);
		std::unique_ptr<Connection> connection = std::make_unique<Connection>(hostIP, hostPort);
		DecentRASession decentRA(connection, expEnc, expEnc);
		decentRA.ProcessClientSideRA();

		Server ser(hostIP, 57756U);
		std::unique_ptr<Connection> connection2 = ser.AcceptConnection();
		DecentRASession decentRA2(connection2, expEnc, expEnc);
		decentRA2.ProcessServerSideRA();
	}
	break;
	case 2:
	{
		expEnc.SetDecentMode(DecentNodeMode::APPL_SERVER);
		std::unique_ptr<Connection> connection = std::make_unique<Connection>(hostIP, 57756U);
		DecentRASession decentRA(connection, expEnc, expEnc);
		decentRA.ProcessClientSideRA();

		Server ser(hostIP, 57750U);
		std::unique_ptr<Connection> connection2 = ser.AcceptConnection();
		DecentRASession decentRA2(connection2, expEnc, expEnc);
		decentRA2.ProcessServerSideRA();
		decentRA2.SwapConnection(connection2);

		std::string buffer;
		connection2->Receive(buffer);
		reader->parse(buffer.c_str(), buffer.c_str() + buffer.size(), &jsonRoot, &errStr);

		RAMessageRevRAReq revMsg(jsonRoot);
		uint64_t secret;
		sgx_aes_gcm_128bit_tag_t secretMac;
		expEnc.GetSimpleSecret(revMsg.GetSenderID(), secret, secretMac);
		SimpleMessage sMsg(expEnc.GetRASenderID(), secret, secretMac);
		connection2->Send(sMsg.ToJsonString());
	}
	break;
	case 3:
	{
		expEnc.SetDecentMode(DecentNodeMode::APPL_SERVER);
		std::unique_ptr<Connection> connection = std::make_unique<Connection>(hostIP, hostPort);
		DecentRASession decentRA(connection, expEnc, expEnc);
		decentRA.ProcessClientSideRA();

		std::unique_ptr<Connection> connection2 = std::make_unique<Connection>(hostIP, 57750U);
		DecentRASession decentRA2(connection2, expEnc, expEnc);
		decentRA2.ProcessClientMessage0();
		decentRA2.SwapConnection(connection2);

		RAMessageRevRAReq revMsg(expEnc.GetRASenderID());
		connection2->Send(revMsg.ToJsonString());

		std::string buffer;
		connection2->Receive(buffer);
		reader->parse(buffer.c_str(), buffer.c_str() + buffer.size(), &jsonRoot, &errStr);

		SimpleMessage sMsg(jsonRoot);
		expEnc.ProcessSimpleSecret(sMsg.GetSenderID(), sMsg.GetSecret(), sMsg.GetSecretMac());

	}
	break;
	default:
		break;
	}

#else
	std::cout << "================ This is client side ================" << std::endl;

	expEnc.SetDecentMode(DecentNodeMode::ROOT_SERVER);
	//std::unique_ptr<Connection> connection(expEnc.RequestRA(hostIP, hostPort));

#endif // RA_SERVER_SIDE

	printf("Enter a character before exit ...\n");
	getchar();
	return 0;
}
