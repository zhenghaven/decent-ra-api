#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL

#include <string>
#include <map>
#include <memory>

#include <sgx_dh.h>

#include "../../common/CommonTool.h"
#include "../../common/DataCoding.h"
#include "../../common/Decent/Crypto.h"
#include "../../common/Decent/States.h"
#include "../../common/Decent/RaReport.h"
#include "../../common/Decent/KeyContainer.h"
#include "../../common/Decent/CertContainer.h"

#include "../../common/SGX/SgxCryptoConversions.h"

#include "../WhiteList/ConstManager.h"

#include "../DecentCrypto.h"

#include "SGXLACommLayer.h"
#include "SgxSelfRaReportGenerator.h"
#include "SgxDecentRaProcessor.h"

//Initialize Decent enclave.
extern "C" sgx_status_t ecall_decent_init(const sgx_spid_t* inSpid)
{
	if (!inSpid)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}
	SgxRaProcessorSp::SetSpid(*inSpid);

	std::string selfHash = Decent::Crypto::GetSelfHashBase64();

	ocall_printf("Enclave Program Hash: %s\n", selfHash.c_str());

	return SGX_SUCCESS;
}

//Deinitialize Decent enclave.
extern "C" void ecall_decent_terminate()
{

}

//Self attestation.
extern "C" sgx_status_t ecall_decent_server_generate_x509(const void * const ias_connector, const uint64_t enclave_Id)
{
	const Decent::KeyContainer& keyContainer = Decent::States::Get().GetKeyContainer();
	std::shared_ptr<const general_secp256r1_public_t> signPub = keyContainer.GetSignPubKey();
	std::shared_ptr<const MbedTlsObj::ECKeyPair> signkeyPair = keyContainer.GetSignKeyPair();

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

//Output cert to the untrusted side.
extern "C" size_t ecall_decent_server_get_x509_pem(char* buf, size_t buf_len)
{
	auto serverCert = Decent::States::Get().GetCertContainer().GetCert();
	if (!serverCert || !(*serverCert))
	{
		return 0;
	}

	const std::string& x509Pem = serverCert->ToPemString();

	std::memcpy(buf, x509Pem.data(), buf_len >= x509Pem.size() ? x509Pem.size() : buf_len);

	return x509Pem.size();
}

//Load const white list to the const white list manager.
extern "C" int ecall_decent_server_load_const_white_list(const char* key, const char* listJson)
{
	return Decent::WhiteList::ConstManager::Get().AddWhiteList(key, listJson);
}

extern "C" sgx_status_t ecall_decent_server_proc_app_cert_req(const char* key, void* const connection)
{
	if (!key || !connection)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	std::string plainMsg;
	SGXLACommLayer commLayer(connection, true);
	const sgx_dh_session_enclave_identity_t* identity = commLayer.GetIdentity();
	if (!identity ||
		!commLayer.ReceiveMsg(connection, plainMsg))
	{
		return SGX_ERROR_UNEXPECTED;
	}
	Decent::X509Req appX509Req(plainMsg);
	if (!appX509Req || !appX509Req.VerifySignature())
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	const Decent::States& globalStates = Decent::States::Get();
	std::shared_ptr<const MbedTlsObj::ECKeyPair> signKey = globalStates.GetKeyContainer().GetSignKeyPair();
	std::shared_ptr<const Decent::ServerX509> serverCert = std::dynamic_pointer_cast<const Decent::ServerX509>(globalStates.GetCertContainer().GetCert());

	if (!serverCert || !*serverCert || 
		!signKey || !*signKey)
	{
		return SGX_ERROR_UNEXPECTED;
	}

	std::string whiteList = Decent::WhiteList::ConstManager::Get().GetWhiteList(key);
	Decent::AppX509 appX509(appX509Req.GetEcPublicKey(), *serverCert, *signKey, SerializeStruct(identity->mr_enclave), Decent::RaReport::sk_ValueReportTypeSgx, SerializeStruct(*identity), whiteList);

	if (!appX509 ||
		!commLayer.SendMsg(connection, appX509.ToPemString()))
	{
		return SGX_ERROR_UNEXPECTED;
	}

	return SGX_SUCCESS;
}

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL
