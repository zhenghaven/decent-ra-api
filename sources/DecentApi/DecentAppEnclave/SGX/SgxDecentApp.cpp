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

#include "../../Common/MbedTls/Drbg.h"
#include "../../Common/MbedTls/EcKey.h"

#include "../../Common/Ra/AppX509Cert.h"
#include "../../Common/Ra/ServerX509Cert.h"
#include "../../Common/Ra/AppX509Req.h"
#include "../../Common/Ra/KeyContainer.h"
#include "../../Common/Ra/WhiteList/LoadedList.h"
#include "../../Common/Ra/WhiteList/DecentServer.h"

#include "../AppStatesSingleton.h"
#include "../AppCertContainer.h"

using namespace Decent::Net;
using namespace Decent::Ra;
using namespace Decent::Tools;
using namespace Decent::MbedTlsObj;
using namespace Decent::Ra::WhiteList;

namespace
{
	static AppStates& gs_appStates = GetAppStateSingleton();
}

extern "C" size_t ecall_decent_ra_app_get_x509_pem(char* buf, size_t buf_len)
{
	auto cert = gs_appStates.GetCertContainer().GetCert();
	if (!cert)
	{
		return 0;
	}

	std::string x509Pem = cert->GetPemChain();
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

		PRINT_I("Initializing Decent App with hash:    %s\n", GetSelfHashBase64().c_str());
		PRINT_I("                      & with pub key: %s\n", SerializeStruct(*keyContainer.GetSignPubKey()).c_str());

		EnclaveCntTranslator cnt(connection);
		Decent::Sgx::LocAttCommLayer commLayer(cnt, false);
		commLayer.SetConnectionPtr(cnt);
		const sgx_dh_session_enclave_identity_t& identity = commLayer.GetIdentity();

		EcKeyPair<EcKeyType::SECP256R1> signKeyPair = *keyContainer.GetSignKeyPair();
		AppX509ReqWriter certReqWrt(HashType::SHA256, signKeyPair, "DecentAppX509Req"); //The name here shouldn't have any effect since it's just a dummy name for the requirement of X509 Req.

		Drbg drbg;
		commLayer.SendContainer(certReqWrt.GenerateDer(drbg));
		std::string appCertPemStr = commLayer.RecvContainer<std::string>();

		//Process X509 Message:

		std::shared_ptr<AppX509Cert> cert = std::make_shared<AppX509Cert>(appCertPemStr);
		if (!cert || !cert->NextCert())
		{
			return SGX_ERROR_UNEXPECTED;
		}

		{
			const ServerX509Cert svrCert(*cert->GetCurr());
			PRINT_I("Received certificate from Decent Server %s.", svrCert.GetCurrCommonName().c_str());
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
