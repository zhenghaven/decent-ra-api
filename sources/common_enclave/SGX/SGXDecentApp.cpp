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

#include "SGXLA.h"
#include "SGXLADecent.h"
#include "SGXDecentCommon.h"

#include "../Common.h"
#include "../../common/JsonTools.h"
#include "../../common/DataCoding.h"
#include "../../common/OpenSSLTools.h"
#include "../../common/DecentRAReport.h"
#include "../../common/AESGCMCommLayer.h"
#include "../../common/EnclaveAsyKeyContainer.h"

#include "../../common/SGX/SGXOpenSSLConversions.h"
#include "../../common/SGX/SGXRAServiceProvider.h"

#include "../../common_enclave/DecentCertContainer.h"

namespace
{
	//Secure comm layer to decent server. (We only attest to one decent server once)
	static std::shared_ptr<const SecureCommLayer> g_decentCommLayer;

	//Hardcoded decent enclave's hash. (Not used until decent program is stable)
	static constexpr char gk_decentHash[] = "";

	//static std::shared_ptr<const sgx_ec256_public_t> g_decentPubKey;
}

static bool CommLayerSendFunc(void* const connectionPtr, const char* senderID, const char *msg, const char* attach)
{
	int retVal = 0;
	sgx_status_t enclaveRet = ocall_decent_la_send_trusted_msg(&retVal, connectionPtr, senderID, msg, attach);
	if (enclaveRet != SGX_SUCCESS)
	{
		return false;
	}
	return retVal == 1;
}

extern "C" sgx_status_t ecall_decent_app_process_ias_ra_report(const char* x509Pem)
{
	auto serverCert = DecentCertContainer::Get().GetServerCert();

	if (!x509Pem || serverCert)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	std::shared_ptr<DecentServerX509> inCert(new DecentServerX509(x509Pem));
	if (!inCert || !(*inCert))
	{
		return SGX_ERROR_UNEXPECTED;
	}

	sgx_ias_report_t iasReport;
	bool verifyRes = DecentEnclave::ProcessIasRaReport(*inCert, gk_decentHash, iasReport);
	//Won't be successful now, since the decent hash is unknown.
	//if (!verifyRes)
	//{
	//	return SGX_ERROR_INVALID_PARAMETER;
	//}

	DecentCertContainer::Get().SetServerCert(inCert);
	//COMMON_PRINTF("Accepted Decent Server.\n%s\n", DecentCertContainer::Get().GetServerCert()->ToPemString().c_str());

	return SGX_SUCCESS;
}

//Send x509 req to decent server.
extern "C" sgx_status_t ecall_decent_app_send_x509_req(const char* decentId, void* const connectionPtr, const char* const appAttach)
{
	if (!decentId || !connectionPtr)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	std::unique_ptr<sgx_dh_session_enclave_identity_t> identity;
	std::unique_ptr<GeneralAES128BitKey> aesKey;
	if (!SGXLAEnclave::ReleasePeerKey(decentId, identity, aesKey) || !identity || !aesKey)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	//=============== Not used now 
	//sgx_measurement_t targetHash;
	//DeserializeStruct(targetHash, gk_decentHash);
	//const sgx_measurement_t& testHash = identity->mr_enclave;

	//if (!consttime_memequal(&targetHash, &testHash, sizeof(sgx_measurement_t)))
	//{
	//	return SGX_ERROR_INVALID_PARAMETER;
	//}
	//===============

	std::shared_ptr<EnclaveAsyKeyContainer> keyContainer = EnclaveAsyKeyContainer::GetInstance();
	std::shared_ptr<const sgx_ec256_public_t> pubKey = keyContainer->GetSignPubKey();
	std::shared_ptr<const ECKeyPair> prvKeyOpenSSL = keyContainer->GetSignPrvKeyOpenSSL();

	std::shared_ptr<const SecureCommLayer> commLayer(new AESGCMCommLayer(*aesKey, SerializeStruct(*pubKey), &CommLayerSendFunc));

	X509ReqWrapper certReq(*prvKeyOpenSSL);
	
	rapidjson::Document doc;
	rapidjson::Value jsonRoot;

	JsonCommonSetString(doc, jsonRoot, SGXLADecent::gsk_LabelFunc, SGXLADecent::gsk_ValueFuncAppX509Req);
	JsonCommonSetString(doc, jsonRoot, SGXLADecent::gsk_LabelX509Req, certReq.ToPemString());

	if (!commLayer->SendMsg(connectionPtr, Json2StyleString(jsonRoot), appAttach))
	{
		return SGX_ERROR_UNEXPECTED;
	}

	g_decentCommLayer = commLayer;

	return SGX_SUCCESS;
}

//Proc application's x509 msg received from server. 
extern "C" sgx_status_t ecall_decent_app_proc_app_x509_msg(const char* jsonMsg)
{
	auto serverCert = DecentCertContainer::Get().GetServerCert();

	if (!g_decentCommLayer || !serverCert || !*serverCert)
	{
		return SGX_ERROR_UNEXPECTED;
	}

	std::shared_ptr<const SecureCommLayer> commLayer = g_decentCommLayer;
	g_decentCommLayer.reset();

	std::string plainMsg;
	if (!commLayer->DecryptMsg(plainMsg, jsonMsg))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	JSON_EDITION::JSON_DOCUMENT_TYPE jsonRoot;
	if (!ParseStr2Json(jsonRoot, plainMsg) ||
		!jsonRoot.HasMember(SGXLADecent::gsk_LabelFunc) || !jsonRoot[SGXLADecent::gsk_LabelFunc].IsString())
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	std::string funcType(jsonRoot[SGXLADecent::gsk_LabelFunc].GetString());

	if (funcType == SGXLADecent::gsk_ValueFuncAppX509)
	{
		if (!jsonRoot.HasMember(SGXLADecent::gsk_LabelAppX509) || !jsonRoot[SGXLADecent::gsk_LabelAppX509].IsString())
		{
			return SGX_ERROR_INVALID_PARAMETER;
		}

		std::shared_ptr<DecentAppX509> cert(new DecentAppX509(jsonRoot[SGXLADecent::gsk_LabelAppX509].GetString()));
		if (!cert || !*cert)
		{
			return SGX_ERROR_UNEXPECTED;
		}

		DecentCertContainer::Get().SetCert(cert);
		//COMMON_PRINTF("Received X509 from Decent Server. \n%s\n", DecentCertContainer::Get().GetCert()->ToPemString().c_str());

		return SGX_SUCCESS;
	}

	return SGX_ERROR_INVALID_PARAMETER;
}

extern "C" size_t ecall_decent_app_get_x509_pem(char* buf, size_t buf_len)
{
	auto cert = DecentCertContainer::Get().GetCert();
	if (!cert || !(*cert))
	{
		return 0;
	}

	std::string x509Pem = cert->ToPemString();
	std::memcpy(buf, x509Pem.data(), buf_len > x509Pem.size() ? x509Pem.size() : buf_len);

	return x509Pem.size();
}

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_APP_INTERNAL
