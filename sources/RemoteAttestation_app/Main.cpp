#include <cstdio>
#include <cstring>

#include <string>
#include <iostream>

#include <tclap/CmdLine.h>
#include <boost/asio/ip/address_v4.hpp>
#include <json/json.h>

#include <sgx_tcrypto.h>

#include "../common/DataCoding.h"
#include "../common/OpenSSLTools.h"
#include "../common/SGX/SGXOpenSSLConversions.h"

#include "../common_app/EnclaveUtil.h"
#include "../common_app/Common.h"
#include "../common_app/DecentRASession.h"

#include "../common_app/Networking/Connection.h"
#include "../common_app/Networking/Server.h"

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
	ASSERT(deviceStatusResErr == SGX_SUCCESS, GetSGXErrorMessage(deviceStatusResErr).c_str());

	IASConnector iasConnector;
	ExampleEnclave expEnc(g_sgxSPID, ENCLAVE_FILENAME, iasConnector, KnownFolderType::LocalAppDataEnclave, TOKEN_FILENAME);

	std::string decentSelfRaReport;
	expEnc.CreateDecentSelfRAReport(decentSelfRaReport);
	expEnc.ProcessDecentSelfRAReport(decentSelfRaReport);

	sgx_ec256_public_t signPubKey;
	expEnc.GetRASPSignPubKey(signPubKey);
	std::string raSenderID = SerializePubKey(signPubKey);

#ifdef SIMULATING_ENCLAVE
	LOGW("Enclave is running under simulation mode!!\n");
#endif // SIMULATING_ENCLAVE


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
		DecentRASession decentRA(connection, expEnc, expEnc, expEnc);
		decentRA.ProcessServerSideRA();

		std::unique_ptr<Connection> connection2 = ser.AcceptConnection();
		DecentRASession decentRA2(connection2, expEnc, expEnc, expEnc);
		decentRA2.ProcessServerSideRA();
	}
	break;
	case 1:
	{
		expEnc.SetDecentMode(DecentNodeMode::ROOT_SERVER);
		std::unique_ptr<Connection> connection = std::make_unique<Connection>(hostIP, hostPort);
		DecentRASession decentRA(connection, expEnc, expEnc, expEnc);
		decentRA.ProcessClientSideRA();

		Server ser(hostIP, 57756U);
		std::unique_ptr<Connection> connection2 = ser.AcceptConnection();
		DecentRASession decentRA2(connection2, expEnc, expEnc, expEnc);
		decentRA2.ProcessServerSideRA();
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
