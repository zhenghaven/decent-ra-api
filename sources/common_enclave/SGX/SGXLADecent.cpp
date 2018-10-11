#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL

#include "SGXLADecent.h"

#define STRUCT_ASSERT_ERROR_MSG "Check sgx_report_body_t and sgx_dh_session_enclave_identity_t has different struct"

#include <string>
#include <memory>
#include <cstring>

#include <sgx_report.h>
#include <sgx_error.h>
#include <sgx_ecp_types.h>
#include <sgx_dh.h>
#include <sgx_tcrypto.h>

#include <Enclave_t.h>

#include "SGXLACommLayer.h"

#include "../DecentCertContainer.h"

#include "../../common/DataCoding.h"
#include "../../common/MbedTlsObjects.h"
#include "../../common/AESGCMCommLayer.h"
#include "../../common/CryptoKeyContainer.h"

static inline sgx_status_t SendAppX509Cert(const sgx_dh_session_enclave_identity_t& identity, const MbedTlsDecentX509Req& x509Req, SecureCommLayer& commLayer, void* const connectionPtr)
{
	std::shared_ptr<const MbedTlsObj::ECKeyPair> signKey = CryptoKeyContainer::GetInstance().GetSignKeyPair();
	std::shared_ptr<const MbedTlsDecentServerX509> serverCert = DecentCertContainer::Get().GetServerCert();

	if (!x509Req.VerifySignature())
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	MbedTlsDecentAppX509 appX509(x509Req.GetEcPublicKey(), *serverCert, *signKey, SerializeStruct(identity.mr_enclave), SGXLADecent::gsk_ValuePlatformType, SerializeStruct(identity));

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


extern "C" sgx_status_t ecall_decent_proc_app_x509_req(const char* peerId, void* const connectionPtr)
{
	auto serverCert = DecentCertContainer::Get().GetServerCert();

	if (!peerId || !connectionPtr || !serverCert || !*serverCert)
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

	MbedTlsDecentX509Req appX509Req(plainMsg);
	if (!appX509Req)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	return SendAppX509Cert(*identity, appX509Req, commLayer, connectionPtr);
}

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL
