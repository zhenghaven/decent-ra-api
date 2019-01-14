#include <memory>

#include <mbedtls/ssl.h>

#include "../common/DecentStates.h"
#include "../common/DecentCrypto.h"
#include "../common/TLSCommLayer.h"
#include "../common/MbedTlsObjects.h"
#include "../common/MbedTlsHelpers.h"
#include "../common/CryptoKeyContainer.h"
#include "../common/DecentCertContainer.h"

#include "../common/CommonTool.h"

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

static MbedTlsObj::TlsConfig ConstructTlsConfig(const MbedTlsObj::ECKeyPair& prvKey, const Decent::AppX509& appCert)
{
	MbedTlsObj::TlsConfig config(new mbedtls_ssl_config);
	config.BasicInit();

	if (mbedtls_ssl_config_defaults(config.GetInternalPtr(), MBEDTLS_SSL_IS_SERVER,
			MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_SUITEB) != 0)
	{
		config.Destroy();
		return config;
	}

	if (prvKey && appCert &&
		mbedtls_ssl_conf_own_cert(config.GetInternalPtr(), appCert.GetInternalPtr(), prvKey.GetInternalPtr()) != 0)
	{
		config.Destroy();
		return config;
	}

	mbedtls_ssl_conf_ca_chain(config.GetInternalPtr(), voteAppCa.GetInternalPtr(), nullptr);
	mbedtls_ssl_conf_authmode(config.GetInternalPtr(), MBEDTLS_SSL_VERIFY_REQUIRED);

	return config;
}

extern "C" int ecall_vote_app_proc_voter_msg(void* connection)
{
	std::shared_ptr<const MbedTlsObj::ECKeyPair> prvKey = CryptoKeyContainer::GetInstance().GetSignKeyPair();
	std::shared_ptr<const Decent::AppX509> appCert = std::dynamic_pointer_cast<const Decent::AppX509>(Decent::States::Get().GetCertContainer().GetCert());

	std::shared_ptr<const MbedTlsObj::TlsConfig> config(std::make_shared<MbedTlsObj::TlsConfig>(ConstructTlsConfig(*prvKey, *appCert)));
	TLSCommLayer testTls(connection, config, true);
	//testTls.ReceiveMsg(connectionPtr, testMsg);
	COMMON_PRINTF("Handshake was %s.\n", testTls ? "SUCCESS" : "FAILED");

	std::string voteBuf;
	testTls.ReceiveMsg(connection, voteBuf);
	COMMON_PRINTF("Receive vote: %d.\n", voteBuf[0]);

	return true;
}
