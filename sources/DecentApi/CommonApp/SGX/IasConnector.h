#pragma once

#include <cstdint>

#include <string>

#include <mbedTLScpp/LibInitializer.hpp>

typedef uint8_t sgx_epid_group_id_t[4];
typedef struct _ra_msg3_t sgx_ra_msg3_t;

namespace Decent
{
	namespace Ias
	{
		class Connector
		{
		public: //static members:

#if !defined(NDEBUG) || defined(EDEBUG)
			static constexpr char const sk_iasUrl[] = "https://api.trustedservices.intel.com/sgx/dev";
#else
			static constexpr char const sk_iasUrl[] = "https://api.trustedservices.intel.com/sgx";
#endif
			static constexpr char const sk_pathSigRl[] = "/attestation/v3/sigrl/";
			static constexpr char const sk_pathReport[] = "/attestation/v3/report";

			static constexpr char const sk_headerLabelSubKey[] = "Ocp-Apim-Subscription-Key";
			static constexpr char const sk_headerLabelReqId[] = "Request-ID";
			static constexpr char const sk_headerLabelSign[] = "X-IASReport-Signature";
			static constexpr char const sk_headerLabelCert[] = "X-IASReport-Signing-Certificate";

			static bool GetRevocationList(const sgx_epid_group_id_t& gid, const std::string& subscriptionKey, std::string & outRevcList);

			static bool GetQuoteReport(const std::string& jsonReqBody, const std::string& subscriptionKey,
				std::string& outReport, std::string& outSign, std::string& outCert);

		public:
			Connector() = delete;

			/**
			 * \brief	Constructor
			 *
			 * \param	subscriptionKey	The subscription key.
			 */
			Connector(const std::string& subscriptionKey);

			/** \brief	Destructor */
			virtual ~Connector();

			virtual bool GetRevocationList(const sgx_epid_group_id_t& gid, std::string& outRevcList) const;

			virtual bool GetQuoteReport(const sgx_ra_msg3_t& msg3, const size_t msg3Size, const std::string& nonce, const bool pseEnabled, std::string& outReport, std::string& outSign, std::string& outCert) const;

		private:
			mbedTLScpp::LibInitializer& m_libInit;
			const std::string m_subscriptionKey;
		};
	}
}
