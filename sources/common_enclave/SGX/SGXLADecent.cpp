#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL

#include "SGXLADecent.h"

#define STRUCT_ASSERT_ERROR_MSG "Check sgx_report_body_t and sgx_dh_session_enclave_identity_t has different struct"

#include <string>
#include <memory>
#include <cstring>
#include <cstddef>

#include <sgx_report.h>
#include <sgx_error.h>
#include <sgx_ecp_types.h>
#include <sgx_dh.h>
#include <sgx_tcrypto.h>

#include <rapidjson/document.h>

#include <Enclave_t.h>

#include "SGXLA.h"

#include "../../common/DataCoding.h"
#include "../../common/JsonTools.h"
#include "../../common/DecentOpenSSL.h"
#include "../../common/AESGCMCommLayer.h"
#include "../../common/EnclaveAsyKeyContainer.h"

#include "../../common_enclave/DecentCertContainer.h"

static bool CommLayerSendFunc(void* const connectionPtr, const char* senderID, const char *msg, const char* appAttach)
{
	int retVal = 0;
	sgx_status_t enclaveRet = ocall_decent_la_send_trusted_msg(&retVal, connectionPtr, senderID, msg, appAttach);
	if (enclaveRet != SGX_SUCCESS)
	{
		return false;
	}
	return retVal == 1;
}

static_assert(sizeof(sgx_report_body_t::cpu_svn) == sizeof(sgx_dh_session_enclave_identity_t::cpu_svn), STRUCT_ASSERT_ERROR_MSG);
static_assert(sizeof(sgx_report_body_t::misc_select) == sizeof(sgx_dh_session_enclave_identity_t::misc_select), STRUCT_ASSERT_ERROR_MSG);
static_assert(sizeof(sgx_report_body_t::reserved1) == sizeof(sgx_dh_session_enclave_identity_t::reserved_1), STRUCT_ASSERT_ERROR_MSG);
static_assert(sizeof(sgx_report_body_t::attributes) == sizeof(sgx_dh_session_enclave_identity_t::attributes), STRUCT_ASSERT_ERROR_MSG);
static_assert(sizeof(sgx_report_body_t::mr_enclave) == sizeof(sgx_dh_session_enclave_identity_t::mr_enclave), STRUCT_ASSERT_ERROR_MSG);
static_assert(sizeof(sgx_report_body_t::reserved2) == sizeof(sgx_dh_session_enclave_identity_t::reserved_2), STRUCT_ASSERT_ERROR_MSG);
static_assert(sizeof(sgx_report_body_t::mr_signer) == sizeof(sgx_dh_session_enclave_identity_t::mr_signer), STRUCT_ASSERT_ERROR_MSG);
static_assert(sizeof(sgx_report_body_t::reserved3) == sizeof(sgx_dh_session_enclave_identity_t::reserved_3), STRUCT_ASSERT_ERROR_MSG);
static_assert(sizeof(sgx_report_body_t::isv_prod_id) == sizeof(sgx_dh_session_enclave_identity_t::isv_prod_id), STRUCT_ASSERT_ERROR_MSG);
static_assert(sizeof(sgx_report_body_t::isv_svn) == sizeof(sgx_dh_session_enclave_identity_t::isv_svn), STRUCT_ASSERT_ERROR_MSG);

static_assert(offsetof(sgx_report_body_t, cpu_svn) == offsetof(sgx_dh_session_enclave_identity_t, cpu_svn), STRUCT_ASSERT_ERROR_MSG);
static_assert(offsetof(sgx_report_body_t, misc_select) == offsetof(sgx_dh_session_enclave_identity_t, misc_select), STRUCT_ASSERT_ERROR_MSG);
static_assert(offsetof(sgx_report_body_t, reserved1) == offsetof(sgx_dh_session_enclave_identity_t, reserved_1), STRUCT_ASSERT_ERROR_MSG);
static_assert(offsetof(sgx_report_body_t, attributes) == offsetof(sgx_dh_session_enclave_identity_t, attributes), STRUCT_ASSERT_ERROR_MSG);
static_assert(offsetof(sgx_report_body_t, mr_enclave) == offsetof(sgx_dh_session_enclave_identity_t, mr_enclave), STRUCT_ASSERT_ERROR_MSG);
static_assert(offsetof(sgx_report_body_t, reserved2) == offsetof(sgx_dh_session_enclave_identity_t, reserved_2), STRUCT_ASSERT_ERROR_MSG);
static_assert(offsetof(sgx_report_body_t, mr_signer) == offsetof(sgx_dh_session_enclave_identity_t, mr_signer), STRUCT_ASSERT_ERROR_MSG);
static_assert(offsetof(sgx_report_body_t, reserved3) == offsetof(sgx_dh_session_enclave_identity_t, reserved_3), STRUCT_ASSERT_ERROR_MSG);
static_assert(offsetof(sgx_report_body_t, isv_prod_id) == offsetof(sgx_dh_session_enclave_identity_t, isv_prod_id), STRUCT_ASSERT_ERROR_MSG);
static_assert(offsetof(sgx_report_body_t, isv_svn) == offsetof(sgx_dh_session_enclave_identity_t, isv_svn), STRUCT_ASSERT_ERROR_MSG);
static_assert(offsetof(sgx_report_body_t, reserved4) == sizeof(sgx_dh_session_enclave_identity_t), STRUCT_ASSERT_ERROR_MSG);

static inline sgx_status_t SendAppX509Cert(const sgx_dh_session_enclave_identity_t& identity, const X509ReqWrapper& x509Req, std::unique_ptr<const SecureCommLayer>& commLayer, void* const connectionPtr, const char* appAttach)
{
	std::shared_ptr<const ECKeyPair> signKey = EnclaveAsyKeyContainer::GetInstance()->GetSignPrvKeyOpenSSL();
	std::shared_ptr<const DecentServerX509> serverCert = DecentCertContainer::Get().GetServerCert();

	if (!x509Req.VerifySignature())
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	DecentAppX509 appX509(x509Req.GetPublicKey(), *serverCert, *signKey, SerializeStruct(identity.mr_enclave), SGXLADecent::gsk_ValuePlatformType, SerializeStruct(identity));

	if (!appX509)
	{
		return SGX_ERROR_UNEXPECTED;
	}

	rapidjson::Document doc;
	rapidjson::Value jsonRoot;


	JsonCommonSetString(doc, jsonRoot, SGXLADecent::gsk_LabelFunc, SGXLADecent::gsk_ValueFuncAppX509);
	JsonCommonSetString(doc, jsonRoot, SGXLADecent::gsk_LabelAppX509, appX509.ToPemString());

	if (!commLayer->SendMsg(connectionPtr, Json2StyleString(jsonRoot), appAttach))
	{
		return SGX_ERROR_UNEXPECTED;
	}

	return SGX_SUCCESS;
}


extern "C" sgx_status_t ecall_decent_proc_send_app_sign_req(const char* peerId, void* const connectionPtr, const char* jsonMsg, const char* appAttach)
{
	auto serverCert = DecentCertContainer::Get().GetServerCert();

	if (!peerId || !connectionPtr || !jsonMsg || !serverCert || !*serverCert)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	std::unique_ptr<sgx_dh_session_enclave_identity_t> identity;
	std::unique_ptr<GeneralAES128BitKey> aesKey;
	if (!SGXLAEnclave::ReleasePeerKey(peerId, identity, aesKey))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	std::shared_ptr<const sgx_ec256_public_t> pubKey = EnclaveAsyKeyContainer::GetInstance()->GetSignPubKey();
	std::unique_ptr<const SecureCommLayer> commLayer(new AESGCMCommLayer(*aesKey, SerializeStruct(*pubKey), &CommLayerSendFunc));

	std::string plainMsg;
	if (!commLayer->DecryptMsg(plainMsg, jsonMsg))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	rapidjson::Document jsonRoot;
	if (!ParseStr2Json(jsonRoot, plainMsg) ||
		!jsonRoot.HasMember(SGXLADecent::gsk_LabelFunc) ||
		!jsonRoot[SGXLADecent::gsk_LabelFunc].IsString())
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	std::string funcType(jsonRoot[SGXLADecent::gsk_LabelFunc].GetString());

	if (funcType == SGXLADecent::gsk_ValueFuncAppX509Req)
	{
		if (!jsonRoot.HasMember(SGXLADecent::gsk_LabelX509Req) || !jsonRoot[SGXLADecent::gsk_LabelX509Req].IsString())
		{
			return SGX_ERROR_INVALID_PARAMETER;
		}

		X509ReqWrapper appX509Req(jsonRoot[SGXLADecent::gsk_LabelX509Req].GetString());

		if (!appX509Req)
		{
			return SGX_ERROR_INVALID_PARAMETER;
		}

		return SendAppX509Cert(*identity, appX509Req, commLayer, connectionPtr, appAttach);
	}

	return SGX_ERROR_INVALID_PARAMETER;
}

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL
