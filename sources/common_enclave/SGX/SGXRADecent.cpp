#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL

#include <string>
#include <map>
#include <memory>

#include "../../common/CommonTool.h"
#include "../../common/DecentStates.h"
#include "../../common/DecentRAReport.h"
#include "../../common/CryptoKeyContainer.h"
#include "../../common/DecentCertContainer.h"

#include "../../common/SGX/SgxRaSpCommLayer.h"
#include "../../common/SGX/SGXCryptoConversions.h"

#include "../WhiteList/ConstManager.h"

#include "../DecentCrypto.h"

#include "SgxSelfRaReportGenerator.h"
#include "SgxDecentRaProcessor.h"
#include "SgxRaClientCommLayer.h"

//Initialize Decent enclave.
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

//Deinitialize Decent enclave.
extern "C" void ecall_decent_terminate()
{

}

//Self attestation.
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

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL
