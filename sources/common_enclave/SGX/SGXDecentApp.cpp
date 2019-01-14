#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_APP_INTERNAL

#include <string>
#include <memory>
#include <cstring>

#include <sgx_report.h>
#include <sgx_error.h>
#include <sgx_ecp_types.h>
#include <sgx_dh.h>
#include <sgx_tcrypto.h>

#include <rapidjson/document.h>

#include <Enclave_t.h>

#include "SGXLACommLayer.h"

#include "../Common.h"
#include "../DecentCrypto.h"
#include "../../common/JsonTools.h"
#include "../../common/DataCoding.h"
#include "../../common/DecentStates.h"
#include "../../common/DecentCrypto.h"
#include "../../common/DecentRAReport.h"
#include "../../common/CryptoKeyContainer.h"
#include "../../common/DecentCertContainer.h"

#include "../../common/SGX/SGXCryptoConversions.h"

namespace
{
	//Hardcoded decent enclave's hash. (Not used until decent program is stable)
	static constexpr char gk_decentHash[] = "";
}

extern "C" sgx_status_t ecall_decent_app_process_ias_ra_report(const char* x509Pem)
{
	//auto serverCert = DecentCertContainer::Get().GetServerCert();

	//if (!x509Pem || serverCert)
	//{
	//	return SGX_ERROR_INVALID_PARAMETER;
	//}

	std::shared_ptr<Decent::ServerX509> inCert(std::make_shared<Decent::ServerX509>(x509Pem));
	if (!inCert || !(*inCert))
	{
		return SGX_ERROR_UNEXPECTED;
	}

	bool verifyRes = Decent::RAReport::ProcessSelfRaReport(inCert->GetPlatformType(), inCert->GetEcPublicKey().ToPubPemString(),
		inCert->GetSelfRaReport(), gk_decentHash);
	//Won't be successful now, since the decent hash is unknown.
	//if (!verifyRes)
	//{
	//	return SGX_ERROR_INVALID_PARAMETER;
	//}

	//DecentCertContainer::Get().SetServerCert(inCert);
	//COMMON_PRINTF("Accepted Decent Server.\n%s\n", DecentCertContainer::Get().GetServerCert()->ToPemString().c_str());

	return SGX_SUCCESS;
}

//Send x509 req to decent server.
extern "C" sgx_status_t ecall_decent_app_get_x509(const char* decentId, void* const connectionPtr)
{//TODO: remove "decentId".
	if (!decentId || !connectionPtr)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	SGXLACommLayer commLayer(connectionPtr, true);
	const sgx_dh_session_enclave_identity_t* identity = commLayer.GetIdentity();
	if (!identity)
	{
		return SGX_ERROR_UNEXPECTED;
	}
	//TODO: check Decent server Hash here instead.
	CryptoKeyContainer& keyContainer = CryptoKeyContainer::GetInstance();
	std::shared_ptr<const MbedTlsObj::ECKeyPair> signKeyPair = keyContainer.GetSignKeyPair();

	Decent::X509Req certReq(*signKeyPair, "DecentAppX509Req"); //The name here shouldn't have any effect since it's just a dummy name for the requirement of X509 Req.
	if (!certReq)
	{
		return SGX_ERROR_UNEXPECTED;
	}

	std::string plainMsg;
	if (!commLayer.SendMsg(connectionPtr, certReq.ToPemString()) ||
		!commLayer.ReceiveMsg(connectionPtr, plainMsg))
	{
		return SGX_ERROR_UNEXPECTED;
	}

	//Process X509 Message:

	std::shared_ptr<Decent::AppX509> cert(new Decent::AppX509(plainMsg));
	if (!cert || !*cert)
	{
		return SGX_ERROR_UNEXPECTED;
	}

	Decent::States::Get().GetCertContainer().SetCert(cert);

	//TODO: We don't need these:
	Decent::Crypto::RefreshDecentAppAppClientSideConfig();
	Decent::Crypto::RefreshDecentAppAppServerSideConfig();
	Decent::Crypto::RefreshDecentAppClientServerSideConfig();

	//COMMON_PRINTF("Received X509 from Decent Server. \n%s\n", Decent::States::Get().GetCertContainer().GetCert()->ToPemString().c_str());

	return SGX_SUCCESS;
}

extern "C" size_t ecall_decent_app_get_x509_pem(char* buf, size_t buf_len)
{
	auto cert = Decent::States::Get().GetCertContainer().GetCert();
	if (!cert || !(*cert))
	{
		return 0;
	}

	std::string x509Pem = cert->ToPemString();
	std::memcpy(buf, x509Pem.data(), buf_len >= x509Pem.size() ? x509Pem.size() : buf_len);

	return x509Pem.size();
}

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_APP_INTERNAL
