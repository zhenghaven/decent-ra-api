#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL

#include <string>
#include <memory>
#include <cstring>

#include <sgx_dh.h>

#include "SGXLACommLayer.h"

#include "../../common/DecentCertContainer.h"

#include "../../common/DataCoding.h"
#include "../../common/DecentCrypto.h"
#include "../../common/DecentRAReport.h"
#include "../../common/MbedTlsObjects.h"
#include "../../common/CryptoKeyContainer.h"

static inline sgx_status_t SendAppX509Cert(const sgx_dh_session_enclave_identity_t& identity, const Decent::X509Req& x509Req, SecureCommLayer& commLayer, void* const connectionPtr)
{
	std::shared_ptr<const MbedTlsObj::ECKeyPair> signKey = CryptoKeyContainer::GetInstance().GetSignKeyPair();
	std::shared_ptr<const Decent::ServerX509> serverCert = DecentCertContainer::Get().GetServerCert();

	if (!x509Req.VerifySignature())
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	Decent::AppX509 appX509(x509Req.GetEcPublicKey(), *serverCert, *signKey, SerializeStruct(identity.mr_enclave), Decent::RAReport::sk_ValueReportTypeSgx, SerializeStruct(identity));

	if (!appX509)
	{
		return SGX_ERROR_UNEXPECTED;
	}

	if (!commLayer.SendMsg(connectionPtr, appX509.ToPemString()))
	{
		return SGX_ERROR_UNEXPECTED;
	}

	return SGX_SUCCESS;
}


extern "C" sgx_status_t ecall_decent_proc_app_x509_req(void* const connectionPtr)
{
	auto serverCert = DecentCertContainer::Get().GetServerCert();

	if (!connectionPtr || !serverCert || !*serverCert)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	SGXLACommLayer commLayer(connectionPtr, false);
	const sgx_dh_session_enclave_identity_t* identity = commLayer.GetIdentity();
	if (!identity)
	{
		return SGX_ERROR_UNEXPECTED;
	}

	std::shared_ptr<const general_secp256r1_public_t> pubKey = CryptoKeyContainer::GetInstance().GetSignPubKey();

	std::string plainMsg;
	if (!commLayer.ReceiveMsg(connectionPtr, plainMsg))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	Decent::X509Req appX509Req(plainMsg);
	if (!appX509Req)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	return SendAppX509Cert(*identity, appX509Req, commLayer, connectionPtr);
}

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL
