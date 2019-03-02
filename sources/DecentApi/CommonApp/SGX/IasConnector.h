#pragma once

#include <cstdint>

#include <string>

typedef uint8_t sgx_epid_group_id_t[4];
typedef struct _ra_msg3_t sgx_ra_msg3_t;

namespace Decent
{
	namespace Ias
	{
		class Connector
		{
		public:
#if !defined(NDEBUG) || defined(EDEBUG)
			static constexpr char const sk_iasUrl[] = "https://test-as.sgx.trustedservices.intel.com:443";
#else
			static constexpr char const sk_iasUrl[] = "https://as.sgx.trustedservices.intel.com:443";
#endif
			static constexpr char const sk_iasSigRlPath[] = "/attestation/sgx/v2/sigrl/";
			static constexpr char const sk_iasReportPath[] = "/attestation/sgx/v2/report";

			/** \brief	Default path to the Service Provider's cert file, which is %HOME%/SGX_IAS/client.crt */
			static const std::string sk_defaultCertPath;

			/** \brief	Default path to the Service Provider's private key file, which is %HOME%/SGX_IAS/client.pem */
			static const std::string sk_defaultKeyPath;

			/** \brief	Default path to the Service Provider's private RSA key file, which is %HOME%/SGX_IAS/client.key */
			//static const std::string sk_defaultRsaKeyPath;

			static bool GetRevocationList(const sgx_epid_group_id_t& gid, const std::string& certPath, const std::string& keyPath,
				std::string & outRevcList);

			static bool GetQuoteReport(const std::string& jsonReqBody, const std::string& certPath, const std::string& keyPath,
				std::string& outReport, std::string& outSign, std::string& outCert);

		public:
			Connector();
			Connector(const std::string& certPath, const std::string& keyPath);
			virtual ~Connector();

			virtual bool GetRevocationList(const sgx_epid_group_id_t& gid, std::string& outRevcList) const;

			virtual bool GetQuoteReport(const sgx_ra_msg3_t& msg3, const size_t msg3Size, const std::string& nonce, const bool pseEnabled, std::string& outReport, std::string& outSign, std::string& outCert) const;

		private:
			const std::string m_certPath;
			const std::string m_keyPath;
		};
	}
}
