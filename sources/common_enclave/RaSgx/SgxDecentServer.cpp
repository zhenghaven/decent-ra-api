#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL

#include <string>
#include <map>
#include <memory>

#include <sgx_dh.h>

#include "../../common/Common.h"
#include "../../common/make_unique.h"
#include "../../common/Tools/DataCoding.h"
#include "../../common/Ra/Crypto.h"
#include "../../common/Ra/States.h"
#include "../../common/Ra/RaReport.h"
#include "../../common/Ra/KeyContainer.h"
#include "../../common/Ra/CertContainer.h"

#include "../../common/SGX/SgxCryptoConversions.h"

#include "../Ra/WhiteList/ConstManager.h"
#include "../Ra/Crypto.h"

#include "../SGX/LocAttCommLayer.h"
#include "../RaSgx/SelfRaReportGenerator.h"
#include "../RaSgx/RaProcessor.h"

using namespace Decent;
using namespace Decent::Ra;
using namespace Decent::Tools;
using namespace Decent::RaSgx;

//Initialize Decent enclave.
extern "C" sgx_status_t ecall_decent_init(const sgx_spid_t* inSpid)
{
	if (!inSpid)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}
	Decent::Sgx::RaProcessorSp::SetSpid(*inSpid);

	std::string selfHash = Decent::Crypto::GetSelfHashBase64();

	LOGI("Enclave Program Hash: %s\n", selfHash.c_str());

	return SGX_SUCCESS;
}

//Deinitialize Decent enclave.
extern "C" void ecall_decent_terminate()
{

}

//Self attestation.
extern "C" sgx_status_t ecall_decent_server_generate_x509(const void * const ias_connector, const uint64_t enclave_Id)
{
	const KeyContainer& keyContainer = States::Get().GetKeyContainer();
	std::shared_ptr<const general_secp256r1_public_t> signPub = keyContainer.GetSignPubKey();
	std::shared_ptr<const MbedTlsObj::ECKeyPair> signkeyPair = keyContainer.GetSignKeyPair();

	std::unique_ptr<Decent::Sgx::RaProcessorSp> spProcesor = RaProcessorSp::GetSgxDecentRaProcessorSp(ias_connector, GeneralEc256Type2Sgx(*signPub));
	std::unique_ptr<RaProcessorClient> clientProcessor = Tools::make_unique<RaProcessorClient>(
		enclave_Id,
		[](const sgx_ec256_public_t& pubKey) {
			return true;
		},
		RaProcessorClient::sk_acceptDefaultConfig
		);

	Decent::RaSgx::SelfRaReportGenerator selfRaReportGener(spProcesor, clientProcessor);
	
	return Decent::RaSgx::SelfRaReportGenerator::GenerateAndStoreServerX509Cert(selfRaReportGener) ? SGX_SUCCESS : SGX_ERROR_UNEXPECTED;
}

//Output cert to the untrusted side.
extern "C" size_t ecall_decent_server_get_x509_pem(char* buf, size_t buf_len)
{
	auto serverCert = States::Get().GetCertContainer().GetCert();
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
	return WhiteList::ConstManager::Get().AddWhiteList(key, listJson);
}

extern "C" sgx_status_t ecall_decent_server_proc_app_cert_req(const char* key, void* const connection)
{
	if (!key || !connection)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	std::string plainMsg;
	Decent::Sgx::LocAttCommLayer commLayer(connection, true);
	const sgx_dh_session_enclave_identity_t* identity = commLayer.GetIdentity();
	if (!identity ||
		!commLayer.ReceiveMsg(connection, plainMsg))
	{
		return SGX_ERROR_UNEXPECTED;
	}
	X509Req appX509Req(plainMsg);
	if (!appX509Req || !appX509Req.VerifySignature())
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	const States& globalStates = States::Get();
	std::shared_ptr<const MbedTlsObj::ECKeyPair> signKey = globalStates.GetKeyContainer().GetSignKeyPair();
	std::shared_ptr<const ServerX509> serverCert = std::dynamic_pointer_cast<const ServerX509>(globalStates.GetCertContainer().GetCert());

	if (!serverCert || !*serverCert || 
		!signKey || !*signKey)
	{
		return SGX_ERROR_UNEXPECTED;
	}

	std::string whiteList = WhiteList::ConstManager::Get().GetWhiteList(key);
	AppX509 appX509(appX509Req.GetEcPublicKey(), *serverCert, *signKey, SerializeStruct(identity->mr_enclave), RaReport::sk_ValueReportTypeSgx, SerializeStruct(*identity), whiteList);

	if (!appX509 ||
		!commLayer.SendMsg(connection, appX509.ToPemString()))
	{
		return SGX_ERROR_UNEXPECTED;
	}

	return SGX_SUCCESS;
}

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL
