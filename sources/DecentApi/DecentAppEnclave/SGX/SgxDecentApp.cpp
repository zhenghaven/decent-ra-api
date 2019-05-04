#include <string>
#include <memory>

#include <sgx_error.h>
#include <sgx_dh.h>

#include "../../CommonEnclave/Tools/Crypto.h"
#include "../../CommonEnclave/Net/EnclaveCntTranslator.h"
#include "../../CommonEnclave/SGX/LocAttCommLayer.h"
#include "../../CommonEnclave/Ra/TlsConfigSameEnclave.h"

#include "../../Common/Common.h"
#include "../../Common/Tools/DataCoding.h"
#include "../../Common/Ra/Crypto.h"
#include "../../Common/Ra/KeyContainer.h"
#include "../../Common/Ra/WhiteList/LoadedList.h"
#include "../../Common/Ra/WhiteList/DecentServer.h"

#include "../AppStatesSingleton.h"
#include "../AppCertContainer.h"

using namespace Decent;
using namespace Decent::Net;
using namespace Decent::Ra;
using namespace Decent::Ra::WhiteList;

namespace
{
	static AppStates& gs_appStates = GetAppStateSingleton();
}

extern "C" size_t ecall_decent_ra_app_get_x509_pem(char* buf, size_t buf_len)
{
	auto cert = gs_appStates.GetCertContainer().GetCert();
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


	try
	{
		const KeyContainer& keyContainer = gs_appStates.GetKeyContainer();

		PRINT_I("Initializing Decent App with hash:    %s\n", Tools::GetSelfHashBase64().c_str());
		PRINT_I("                      & with pub key: %s\n", Tools::SerializeStruct(*keyContainer.GetSignPubKey()).c_str());

		EnclaveCntTranslator cnt(connection);
		Decent::Sgx::LocAttCommLayer commLayer(cnt, false);
		commLayer.SetConnectionPtr(cnt);
		const sgx_dh_session_enclave_identity_t& identity = commLayer.GetIdentity();

		std::shared_ptr<const MbedTlsObj::ECKeyPair> signKeyPair = keyContainer.GetSignKeyPair();
		X509Req certReq(*signKeyPair, "DecentAppX509Req"); //The name here shouldn't have any effect since it's just a dummy name for the requirement of X509 Req.
		if (!certReq)
		{
			return SGX_ERROR_UNEXPECTED;
		}

		std::string plainMsg;
		commLayer.SendMsg(certReq.ToPemString());
		commLayer.ReceiveMsg(plainMsg);

		//Process X509 Message:

		std::shared_ptr<AppX509> cert = std::make_shared<AppX509>(plainMsg);
		if (!cert || !*cert)
		{
			return SGX_ERROR_UNEXPECTED;
		}

		//Set loaded whitelist.
		WhiteList::LoadedList loadedList(*cert);
		gs_appStates.GetLoadedWhiteList(&loadedList);

		gs_appStates.GetAppCertContainer().SetAppCert(cert);

		TlsConfigSameEnclave tlsCfg(gs_appStates, TlsConfig::Mode::ClientHasCert, nullptr);
		//if (!cert->Verify(, nullptr, nullptr, &TlsConfigSameEnclave::CertVerifyCallBack, tlsCfg))
		//{
		//	PRINT_I("Could not verify the identity of the Decent Server.");
		//	return SGX_ERROR_UNEXPECTED;
		//}
	}
	catch (const std::exception& e)
	{
		PRINT_W("Failed to initialize Decent App. Caught exception: %s", e.what());
		return SGX_ERROR_UNEXPECTED;
	}

	return SGX_SUCCESS;
}
