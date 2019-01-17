#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_APP_INTERNAL

#include <string>
#include <memory>

#include <Enclave_t.h>

#include "../SGX/LocAttCommLayer.h"

#include "../Common.h"
#include "../../common/Decent/States.h"
#include "../../common/Decent/Crypto.h"
#include "../../common/Decent/KeyContainer.h"
#include "../../common/Decent/CertContainer.h"

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

extern "C" sgx_status_t ecall_decent_app_init(void* connection)
{
	if (!connection)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	Sgx::LocAttCommLayer commLayer(connection, false);
	const sgx_dh_session_enclave_identity_t* identity = commLayer.GetIdentity();
	if (!identity)
	{
		return SGX_ERROR_UNEXPECTED;
	}

	//TODO: check Decent server Hash here instead.

	Decent::KeyContainer& keyContainer = Decent::States::Get().GetKeyContainer();
	std::shared_ptr<const MbedTlsObj::ECKeyPair> signKeyPair = keyContainer.GetSignKeyPair();
	Decent::X509Req certReq(*signKeyPair, "DecentAppX509Req"); //The name here shouldn't have any effect since it's just a dummy name for the requirement of X509 Req.
	if (!certReq)
	{
		return SGX_ERROR_UNEXPECTED;
	}

	std::string plainMsg;
	if (!commLayer.SendMsg(connection, certReq.ToPemString()) ||
		!commLayer.ReceiveMsg(connection, plainMsg))
	{
		return SGX_ERROR_UNEXPECTED;
	}

	//Process X509 Message:

	std::shared_ptr<Decent::AppX509> cert = std::make_shared<Decent::AppX509>(plainMsg);
	if (!cert || !*cert)
	{
		return SGX_ERROR_UNEXPECTED;
	}

	Decent::States::Get().GetCertContainer().SetCert(cert);
	Decent::States::Get().GetLoadedWhiteList(cert.get());

	return SGX_SUCCESS;
}

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_APP_INTERNAL
