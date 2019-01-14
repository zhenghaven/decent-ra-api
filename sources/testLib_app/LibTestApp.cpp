
#include <cstdio>

#include <iostream>
#include <string>

#include <sgx_uae_service.h>

#include <boost/asio/ip/address_v4.hpp>
#include <mbedtls/x509_crt.h>
#include <mbedtls/ssl.h>

#include "../common/DecentStates.h"
#include "../common/DecentCertContainer.h"
#include "../common/CryptoKeyContainer.h"
#include "../common/MbedTlsObjects.h"
#include "../common/MbedTlsHelpers.h"
#include "../common/DecentRAReport.h"
#include "../common/DecentCrypto.h"
#include "../common/TLSCommLayer.h"
#include "../common_app/Networking/TCPConnection.h"

#include "../DecentApp_app/VoteAppMessage.h"

#ifdef _MSC_VER

std::string GetSGXDeviceStatusStr(const sgx_device_status_t& sgx_device_status)
{
	switch (sgx_device_status) {
	case SGX_ENABLED:
		return "The platform is enabled for Intel SGX.";
	case SGX_DISABLED_REBOOT_REQUIRED:
		return "SGX device has been enabled. Please reboot your machine.";
	case SGX_DISABLED_LEGACY_OS:
		return "SGX device can't be enabled on an OS that doesn't support EFI interface.";
	case SGX_DISABLED:
		return "SGX is not enabled on this platform. More details are unavailable.";
	case SGX_DISABLED_SCI_AVAILABLE:
		return "SGX device can be enabled by a Software Control Interface.";
	case SGX_DISABLED_MANUAL_ENABLE:
		return "SGX device can be enabled manually in the BIOS setup.";
	case SGX_DISABLED_HYPERV_ENABLED:
		return "Detected an unsupported version of Windows* 10 with Hyper-V enabled.";
	case SGX_DISABLED_UNSUPPORTED_CPU:
		return "SGX is not supported by this CPU.";
	default:
		return "Unexpected error.";
	}
}

#endif

static constexpr char const voteAppCaStr[] = "-----BEGIN CERTIFICATE-----\n\
MIIBdTCCARqgAwIBAgILAJLcv58ab0wEwA4wDAYIKoZIzj0EAwIFADAiMSAwHgYD\n\
VQQDExdEZWNlbnQgVm90ZSBBcHAgUm9vdCBDQTAgFw0xODEwMjIxMDMyMjFaGA8y\n\
MDg2MTEwOTEzNDYyOFowIjEgMB4GA1UEAxMXRGVjZW50IFZvdGUgQXBwIFJvb3Qg\n\
Q0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARiHmZy/OFVfF82RUGKQ/24CQH/\n\
Zb3pcEg1enLmyzH3TLNPTa11v2KuWyu5+t46eBg5B/YH0b0o6HpzzxnsbOQCozMw\n\
MTAMBgNVHRMEBTADAQH/MA4GA1UdDwEB/wQEAwIBzjARBglghkgBhvhCAQEEBAMC\n\
AMQwDAYIKoZIzj0EAwIFAANHADBEAiBvii+PgcSb13JBHPSD2FPIOmMxI6TeHDrp\n\
tNv/Ivr6DgIgJQ5ZX3y8zE+dIf/Ox+lAGZrNnoqgOyZrmi0OD29ssCw=\n\
-----END CERTIFICATE-----";

static const MbedTlsObj::X509Cert voteAppCa(voteAppCaStr);

static MbedTlsObj::TlsConfig ConstructTlsConfig(const MbedTlsObj::ECKeyPair& prvKey, const MbedTlsObj::X509Cert& cert,
	const Decent::ServerX509& decentCert)
{
	MbedTlsObj::TlsConfig config(new mbedtls_ssl_config);
	config.BasicInit();

	if (mbedtls_ssl_config_defaults(config.GetInternalPtr(), MBEDTLS_SSL_IS_CLIENT,
		MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_SUITEB) != 0)
	{
		config.Destroy();
		return config;
	}

	if (!prvKey || !cert ||
		mbedtls_ssl_conf_own_cert(config.GetInternalPtr(), cert.GetInternalPtr(), prvKey.GetInternalPtr()) != 0)
	{
		config.Destroy();
		return config;
	}

	mbedtls_ssl_conf_ca_chain(config.GetInternalPtr(), decentCert.GetInternalPtr(), nullptr);
	mbedtls_ssl_conf_authmode(config.GetInternalPtr(), MBEDTLS_SSL_VERIFY_REQUIRED);

	return config;
}

int main() {

	uint32_t hostIP = boost::asio::ip::address_v4::from_string("127.0.0.1").to_uint();
	uint16_t hostPort = 57755U;

	std::string serverKeyPem = "-----BEGIN EC PRIVATE KEY-----\n\
MHcCAQEEIAQmvQO92cvo/q4j5To+3E797wyqRrWRoqvRTo4VB/kroAoGCCqGSM49\n\
AwEHoUQDQgAEYh5mcvzhVXxfNkVBikP9uAkB/2W96XBINXpy5ssx90yzT02tdb9i\n\
rlsrufreOngYOQf2B9G9KOh6c88Z7GzkAg==\n\
-----END EC PRIVATE KEY-----";
	std::shared_ptr<MbedTlsObj::ECKeyPair> serverKey(std::make_shared<MbedTlsObj::ECKeyPair>(serverKeyPem));

	std::shared_ptr<MbedTlsObj::ECKeyPair> clientKey(std::make_shared<MbedTlsObj::ECKeyPair>(MbedTlsObj::gen));

	std::shared_ptr<MbedTlsObj::X509Cert> clientCert(std::make_shared<MbedTlsObj::X509Cert>(voteAppCa, *serverKey, *clientKey, 
		MbedTlsObj::BigNumber::GenRandomNumber(10), LONG_MAX, true, -1,
		MBEDTLS_X509_KU_NON_REPUDIATION | MBEDTLS_X509_KU_DIGITAL_SIGNATURE | MBEDTLS_X509_KU_KEY_AGREEMENT | MBEDTLS_X509_KU_KEY_CERT_SIGN | MBEDTLS_X509_KU_CRL_SIGN,
		MBEDTLS_X509_NS_CERT_TYPE_SSL_CA | MBEDTLS_X509_NS_CERT_TYPE_SSL_CLIENT | MBEDTLS_X509_NS_CERT_TYPE_SSL_SERVER,
		"CN=Decent Voter",
		std::map<std::string, std::pair<bool, std::string> >()));

	Decent::States::Get().GetCertContainer().SetCert(clientCert);
	CryptoKeyContainer::GetInstance().UpdateSignKeyPair(clientKey);

	std::unique_ptr<Connection> connection = std::make_unique<TCPConnection>(hostIP, hostPort + 5);

	connection->SendPack(VoteAppHandshake(clientKey->ToPubPemString()));
	
	Json::Value recvJson;
	connection->ReceivePack(recvJson);
	VoteAppHandshakeAck hsAck(recvJson);

	std::shared_ptr<Decent::ServerX509> decentCert(std::make_shared<Decent::ServerX509>(hsAck.GetSelfRAReport()));
	bool verifyRes = Decent::RAReport::ProcessSelfRaReport(decentCert->GetPlatformType(), decentCert->GetEcPublicKey().ToPubPemString(),
		decentCert->GetSelfRaReport(), "");

	Decent::Crypto::AppIdVerfier appIdVerifier = [](const MbedTlsObj::ECKeyPublic&, const std::string&, const std::string&)
	{
		return true;
	};
	std::shared_ptr<const MbedTlsObj::TlsConfig> config(std::make_shared<MbedTlsObj::TlsConfig>(Decent::TlsConfig(appIdVerifier, false)));
	TLSCommLayer testTls(connection.get(), config, true);

	std::string voteBuf(1, '\0');
	voteBuf[0] = 1;
	testTls.SendMsg(connection.get(), voteBuf);
	std::cout << "Done! Enter anything to exit..." << std::endl;
	getchar();

	return 0;
}
