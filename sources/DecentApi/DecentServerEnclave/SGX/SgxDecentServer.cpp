#include <string>
#include <map>
#include <memory>

#include <sgx_dh.h>

#include "../../Common/Common.h"
#include "../../Common/make_unique.h"
#include "../../Common/Tools/DataCoding.h"
#include "../../Common/Ra/Crypto.h"
#include "../../Common/Ra/RaReport.h"
#include "../../Common/Ra/KeyContainer.h"

#include "../../Common/SGX/SgxCryptoConversions.h"

#include "../../CommonEnclave/Ra/WhiteList/ConstManager.h"
#include "../../CommonEnclave/Ra/Crypto.h"
#include "../../CommonEnclave/SGX/LocAttCommLayer.h"

#include "RaProcessor.h"
#include "SelfRaReportGenerator.h"
#include "../ServerStatesSingleton.h"

using namespace Decent;
using namespace Decent::Ra;
using namespace Decent::Tools;
using namespace Decent::RaSgx;

namespace
{
	static ServerStates& gs_serverState = GetServerStateSingleton();
}

//Initialize Decent enclave.
extern "C" sgx_status_t ecall_decent_ra_server_init(const sgx_spid_t* inSpid)
{
	if (!inSpid)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}
	Decent::Sgx::RaProcessorSp::SetSpid(*inSpid);
	
	PRINT_I("Initializing Decent Server with hash: %s\n", Decent::Crypto::GetSelfHashBase64().c_str());

	return SGX_SUCCESS;
}

//Deinitialize Decent enclave.
extern "C" void ecall_decent_ra_server_terminate()
{

}

//Self attestation.
extern "C" sgx_status_t ecall_decent_ra_server_gen_x509(const void * const ias_connector, const uint64_t enclave_Id)
{
	const KeyContainer& keyContainer = gs_serverState.GetKeyContainer();
	std::shared_ptr<const general_secp256r1_public_t> signPub = keyContainer.GetSignPubKey();
	std::shared_ptr<const MbedTlsObj::ECKeyPair> signkeyPair = keyContainer.GetSignKeyPair();

	std::unique_ptr<Decent::Sgx::RaProcessorSp> spProcesor = RaProcessorSp::GetSgxDecentRaProcessorSp(ias_connector, GeneralEc256Type2Sgx(*signPub), gs_serverState);
	std::unique_ptr<RaProcessorClient> clientProcessor = Tools::make_unique<RaProcessorClient>(
		enclave_Id,
		[](const sgx_ec256_public_t& pubKey) {
			return true;
		},
		RaProcessorClient::sk_acceptDefaultConfig,
		gs_serverState
		);

	Decent::RaSgx::SelfRaReportGenerator selfRaReportGener(spProcesor, clientProcessor);
	
	return Decent::RaSgx::SelfRaReportGenerator::GenerateAndStoreServerX509Cert(selfRaReportGener, gs_serverState) ? SGX_SUCCESS : SGX_ERROR_UNEXPECTED;
}

//Output cert to the untrusted side.
extern "C" size_t ecall_decent_ra_server_get_x509_pem(char* buf, size_t buf_len)
{
	auto serverCert = gs_serverState.GetServerCertContainer().GetServerCert();
	if (!serverCert || !(*serverCert))
	{
		return 0;
	}

	const std::string& x509Pem = serverCert->ToPemString();

	std::memcpy(buf, x509Pem.data(), buf_len >= x509Pem.size() ? x509Pem.size() : buf_len);

	return x509Pem.size();
}

//Load const white list to the const white list manager.
extern "C" int ecall_decent_ra_server_load_const_loaded_list(const char* key, const char* listJson)
{
	return WhiteList::ConstManager::Get().AddWhiteList(key, listJson);
}

extern "C" sgx_status_t ecall_decent_ra_server_proc_app_cert_req(const char* key, void* const connection)
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

	std::shared_ptr<const MbedTlsObj::ECKeyPair> signKey = gs_serverState.GetKeyContainer().GetSignKeyPair();
	std::shared_ptr<const ServerX509> serverCert = gs_serverState.GetServerCertContainer().GetServerCert();

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
