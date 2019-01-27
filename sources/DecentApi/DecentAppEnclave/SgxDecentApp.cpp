#include <string>
#include <memory>

#include <sgx_error.h>

#include "../CommonEnclave/SGX/LocAttCommLayer.h"

#include "../Common/Common.h"
#include "../Common/Ra/States.h"
#include "../Common/Ra/Crypto.h"
#include "../Common/Ra/KeyContainer.h"
#include "../Common/Ra/CertContainer.h"

using namespace Decent;
using namespace Decent::Ra;

extern "C" size_t ecall_decent_ra_app_get_x509_pem(char* buf, size_t buf_len)
{
	auto cert = States::Get().GetCertContainer().GetCert();
	if (!cert || !(*cert))
	{
		return 0;
	}

	std::string x509Pem = cert->ToPemString();
	std::memcpy(buf, x509Pem.data(), buf_len >= x509Pem.size() ? x509Pem.size() : buf_len);

	return x509Pem.size();
}

extern "C" sgx_status_t ecall_decent_ra_app_init(void* connection)
{
	if (!connection)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	Decent::Sgx::LocAttCommLayer commLayer(connection, false);
	const sgx_dh_session_enclave_identity_t* identity = commLayer.GetIdentity();
	if (!identity)
	{
		return SGX_ERROR_UNEXPECTED;
	}

	//TODO: check Decent server Hash here instead.

	KeyContainer& keyContainer = States::Get().GetKeyContainer();
	std::shared_ptr<const MbedTlsObj::ECKeyPair> signKeyPair = keyContainer.GetSignKeyPair();
	X509Req certReq(*signKeyPair, "DecentAppX509Req"); //The name here shouldn't have any effect since it's just a dummy name for the requirement of X509 Req.
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

	std::shared_ptr<AppX509> cert = std::make_shared<AppX509>(plainMsg);
	if (!cert || !*cert)
	{
		return SGX_ERROR_UNEXPECTED;
	}

	States::Get().GetCertContainer().SetCert(cert);
	States::Get().GetLoadedWhiteList(cert.get());

	return SGX_SUCCESS;
}
