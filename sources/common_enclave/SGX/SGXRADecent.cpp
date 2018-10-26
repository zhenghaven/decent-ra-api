#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL

#include <string>
#include <map>
#include <memory>

#include "../../common/CommonTool.h"
#include "../../common/DecentRAReport.h"
#include "../../common/CryptoKeyContainer.h"
#include "../../common/DecentCertContainer.h"

#include "../../common/SGX/SgxRaSpCommLayer.h"
#include "../../common/SGX/SGXCryptoConversions.h"

#include "../DecentCrypto.h"

#include "SgxSelfRaReportGenerator.h"
#include "SgxDecentRaProcessor.h"
#include "SgxRaClientCommLayer.h"

extern "C" sgx_status_t ecall_decent_init(const sgx_spid_t* inSpid)
{
	if (!inSpid)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}
	SgxRaProcessorSp::SetSpid(*inSpid);

	std::string selfHash = Decent::Crypto::GetProgSelfHashBase64();

	ocall_printf("Enclave Program Hash: %s\n", selfHash.c_str());

	return SGX_SUCCESS;
}

extern "C" void ecall_decent_terminate()
{

}

extern "C" sgx_status_t ecall_decent_server_generate_x509(const void * const ias_connector, const uint64_t enclave_Id)
{
	std::shared_ptr<const general_secp256r1_public_t> signPub = CryptoKeyContainer::GetInstance().GetSignPubKey();
	std::shared_ptr<const MbedTlsObj::ECKeyPair> signkeyPair = CryptoKeyContainer::GetInstance().GetSignKeyPair();

	std::unique_ptr<SgxRaProcessorSp> spProcesor = SgxDecentRaProcessorSp::GetSgxDecentRaProcessorSp(ias_connector, GeneralEc256Type2Sgx(*signPub));
	std::unique_ptr<SgxDecentRaProcessorClient> clientProcessor = Common::make_unique<SgxDecentRaProcessorClient>(
		enclave_Id,
		[](const sgx_ec256_public_t& pubKey) {
			return true;
		},
		SgxDecentRaProcessorClient::sk_acceptDefaultConfig
		);

	SgxSelfRaReportGenerator selfRaReportGener(spProcesor, clientProcessor);
	
	return SelfRaReportGenerator::GenerateAndStoreServerX509Cert(selfRaReportGener) ? SGX_SUCCESS : SGX_ERROR_UNEXPECTED;
}

extern "C" size_t ecall_decent_server_get_x509_pem(char* buf, size_t buf_len)
{
	auto serverCert = DecentCertContainer::Get().GetServerCert();
	if (!serverCert || !(*serverCert))
	{
		return 0;
	}

	const std::string& x509Pem = serverCert->ToPemString();

	if (buf && buf_len >= x509Pem.size())
	{
		std::memcpy(buf, x509Pem.data(), x509Pem.size());
	}

	return x509Pem.size();
}

extern "C" int ecall_decent_process_ias_ra_report(const char* x509Pem)
{
	auto serverCert = DecentCertContainer::Get().GetServerCert();

	if (!x509Pem || serverCert)
	{
		return 0;
	}

	std::shared_ptr<Decent::ServerX509> inCert(new Decent::ServerX509(x509Pem));
	if (!inCert || !(*inCert))
	{
		return 0;
	}

	if (!Decent::RAReport::ProcessSelfRaReport(inCert->GetPlatformType(), inCert->GetEcPublicKey().ToPubPemString(),
		inCert->GetSelfRaReport(), Decent::Crypto::GetProgSelfHashBase64()))
	{
		return 0;
	}
	DecentCertContainer::Get().SetServerCert(inCert);
	//COMMON_PRINTF("Accepted New Decent Node: %s\n", g_decentProtoPubKey.c_str());

	return 1;
}

//This function will be call at new node side.
extern "C" sgx_status_t ecall_decent_recv_proto_key(void* const connection, const uint64_t enclave_id)
{
	std::shared_ptr<const Decent::ServerX509> serverCert = DecentCertContainer::Get().GetServerCert();
	if (!serverCert || !*serverCert || !connection)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	std::unique_ptr<SgxRaProcessorClient> raProcessor = Common::make_unique<SgxRaProcessorClient>(enclave_id, 
		SgxDecentRaProcessorClient::sk_acceptServerKey, SgxDecentRaProcessorClient::sk_acceptDefaultConfig);
	SgxRaClientCommLayer commLayer(connection, raProcessor);
	if (!commLayer)
	{
		return SGX_ERROR_UNEXPECTED;
	}

	std::string plainMsg;
	if (!commLayer.ReceiveMsg(connection, plainMsg))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	std::shared_ptr<const MbedTlsObj::ECKeyPair> protoKeyPair(new MbedTlsObj::ECKeyPair(plainMsg));
	if (!protoKeyPair || !*protoKeyPair ||
		!CryptoKeyContainer::GetInstance().UpdateSignKeyPair(protoKeyPair))
	{
		return SGX_ERROR_UNEXPECTED;
	}

	std::shared_ptr<const Decent::AppX509> dummyAppCert(new Decent::AppX509(*protoKeyPair, *serverCert, *protoKeyPair,
		Decent::Crypto::GetProgSelfHashBase64(), Decent::RAReport::sk_ValueReportTypeSgx, ""));
	DecentCertContainer::Get().SetCert(dummyAppCert);

	Decent::Crypto::RefreshDecentAppAppClientSideConfig();
	Decent::Crypto::RefreshDecentAppAppServerSideConfig();
	Decent::Crypto::RefreshDecentAppClientServerSideConfig();

	//std::string testMsg;
	//TLSCommLayer testTls(connectionPtr, Decent::Crypto::GetDecentAppAppClientSideConfig(), true);
	//testTls.ReceiveMsg(connectionPtr, testMsg);
	//COMMON_PRINTF("TLS Test Msg: %s.\n", testMsg.c_str());

	COMMON_PRINTF("Joined Decent network.\n");

	return SGX_SUCCESS;
}

//This function will be call at existing node side.
extern "C" sgx_status_t ecall_decent_send_protocol_key(void* const connection, const void* const ias_connector)
{
	std::shared_ptr<const Decent::ServerX509> serverCert = DecentCertContainer::Get().GetServerCert();

	if (!connection || !serverCert || !*serverCert)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	std::unique_ptr<SgxRaProcessorSp> raProcessor = Common::make_unique<SgxRaProcessorSp>(
		ias_connector, CryptoKeyContainer::GetInstance().GetSignKeyPair(), 
		Decent::RAReport::GetSgxDecentRaConfig(), SgxRaProcessorSp::sk_defaultRpDataVrfy,
		SgxDecentRaProcessorSp::defaultServerQuoteVerifier
		);
	SgxRaSpCommLayer commLayer(connection, raProcessor);
	if (!commLayer)
	{
		return SGX_ERROR_UNEXPECTED;
	}

	COMMON_PRINTF("Accepted New Decent Node.\n");

	bool res = commLayer.SendMsg(connection, CryptoKeyContainer::GetInstance().GetSignKeyPair()->ToPrvPemString());

	//std::string testMsg = "Enclave Test Message.";
	//TLSCommLayer testTls(connectionPtr, Decent::Crypto::GetDecentAppAppServerSideConfig(), true);
	//testTls.SendMsg(connectionPtr, testMsg);
	//COMMON_PRINTF("TLS Test Msg: %s.\n", testMsg.c_str());

	return res ?
		SGX_SUCCESS : SGX_ERROR_UNEXPECTED;
}

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL
