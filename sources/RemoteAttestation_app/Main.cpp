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
#include "../common_app/DecentRASession.h"

#include "../common_app/Networking/Connection.h"
#include "../common_app/Networking/Server.h"

#include "../common_app/SGX/IAS/IASConnector.h"
#include "../common_app/RAMessageRevRAReq.h"

#include "ExampleEnclave.h"
#include "SimpleMessage.h"

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
	// K: 2b7e1516 28aed2a6 abf71588 09cf4f3c
	sgx_cmac_128bit_key_t key = { 0x2b,0x7e,0x15,0x16,
		0x28,0xae,0xd2,0xa6,
		0xab,0xf7,0x15,0x88,
		0x09,0xcf,0x4f,0x3c };

	// M: 6bc1bee2 2e409f96 e93d7e11 7393172a Mlen: 128
	unsigned char message[] = { 0x6b,0xc1,0xbe,0xe2,
		0x2e,0x40,0x9f,0x96,
		0xe9,0x3d,0x7e,0x11,
		0x73,0x93,0x17,0x2a };
	sgx_status_t enclaveRes = SGX_SUCCESS;
	//sgx_cmac_128bit_tag_t cmacTag1;
	//sgx_cmac_128bit_tag_t cmacTag2;
	// = sgx_rijndael128_cmac_msg(&key, message, sizeof(message), &cmacTag1);
	//enclaveRes = expEnc.CryptoTest(&key, message, sizeof(message), &cmacTag2);
	//auto cmpRes = std::memcmp(cmacTag1, cmacTag2, sizeof(sgx_cmac_128bit_tag_t));
	sgx_ec256_private_t prv;
	sgx_ec256_public_t pub;
	sgx_ecc_state_handle_t ctx = nullptr;
	enclaveRes = sgx_ecc256_create_key_pair(&prv, &pub, ctx);

	sgx_ec256_public_t peerPub;
	sgx_ec256_dh_shared_t sharedKey1;
	sgx_ec256_dh_shared_t sharedKey2;
	expEnc.GetRAEncrPubKey(peerPub);
	enclaveRes = sgx_ecc256_compute_shared_dhkey(&prv, &peerPub, &sharedKey1, ctx);

	expEnc.CryptoTest(&pub, &sharedKey2);
	auto cmpRes = std::memcmp(&sharedKey1, &sharedKey2, sizeof(sgx_ec256_dh_shared_t));

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
	case 2:
	{
		expEnc.SetDecentMode(DecentNodeMode::APPL_SERVER);
		std::unique_ptr<Connection> connection = std::make_unique<Connection>(hostIP, 57756U);
		DecentRASession decentRA(connection, expEnc, expEnc, expEnc);
		decentRA.ProcessClientSideRA();

		Server ser(hostIP, 57750U);
		std::unique_ptr<Connection> connection2 = ser.AcceptConnection();
		DecentRASession decentRA2(connection2, expEnc, expEnc, expEnc);
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
		DecentRASession decentRA(connection, expEnc, expEnc, expEnc);
		decentRA.ProcessClientSideRA();

		std::unique_ptr<Connection> connection2 = std::make_unique<Connection>(hostIP, 57750U);
		DecentRASession decentRA2(connection2, expEnc, expEnc, expEnc);
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
