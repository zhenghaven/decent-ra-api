#pragma once

#include <cstdint>

#include <string>

#include "../Exceptions.h"

typedef struct _sgx_ias_report_t sgx_ias_report_t;
typedef struct _sgx_ra_config sgx_ra_config;

namespace Decent
{
	namespace Ias
	{
		enum class IasQuoteStatus : uint8_t {
			OK                          = 0,
			SIGNATURE_INVALID           = 1,
			GROUP_REVOKED               = 2,
			SIGNATURE_REVOKED           = 3,
			KEY_REVOKED                 = 4,
			SIGRL_VERSION_MISMATCH      = 5,
			GROUP_OUT_OF_DATE           = 6,
			CONFIGURATION_NEEDED        = 7,
		};

		// Revocation Reasons from RFC5280
		enum class IasRevocReason : uint8_t {
			UNSPECIFIED              = 0, //RFC5280 - 0
			KEY_COMPROMISE           = 1, //RFC5280 - 1
			CA_COMPROMISED           = 2, //RFC5280 - 2
			AFFILIATION_CHANGED      = 3, //RFC5280 - 3
			SUPERCEDED               = 4, //RFC5280 - 4
			CESSATION_OF_OPERATION   = 5, //RFC5280 - 5
			CERTIFICATE_HOLD         = 6, //RFC5280 - 6
			REMOVE_FROM_CRL          = 8, //RFC5280 - 8
			PRIVILEGE_WITHDRAWN      = 9, //RFC5280 - 9
			AA_COMPROMISE            = 10, //RFC5280 - 10
		};

		enum class IasPseStatus : uint8_t{
			NA                       = 0,
			OK                       = 1,
			UNKNOWN                  = 2,
			INVALID                  = 3,
			OUT_OF_DATE              = 4,
			REVOKED                  = 5,
			RL_VERSION_MISMATCH      = 6,
		};

		class ReportParseError : public RuntimeException
		{
		public:
			using RuntimeException::RuntimeException;
		};

		/**
		 * \brief	Check Quote status and PSE status stated in the IAS report, based on the requirement
		 * 			set in the RA config. No exception, only logical expressions.
		 *
		 * \param	iasReport	The input for parsed IAS report.
		 * \param	raConfig 	The input for RA configuration.
		 *
		 * \return	True if it is considered as valid according to the configuration, false if not.
		 */
		bool CheckIasReportStatus(const sgx_ias_report_t& iasReport, const sgx_ra_config& raConfig) noexcept;

		/**
		 * \brief	Check if two RA configurations are equal
		 *
		 * \param	a	configuration A.
		 * \param	b	configuration B.
		 *
		 * \return	True if A == B, false if not.
		 */
		bool CheckRaConfigEqual(const sgx_ra_config& a, const sgx_ra_config& b) noexcept;

		/**
		 * \brief	Check RA configuration's validity. which means all values must be within the possible range.
		 *
		 * \param	a	A sgx_ra_config to check.
		 *
		 * \return	True if it it valid, false if not.
		 */
		bool CheckRaConfigValidaty(const sgx_ra_config& a) noexcept;

		/**
		 * \brief	This function only parses IAS's report
		 *
		 * \exception	Ias::ReportParseError	The IAS report has unrecognized format (probably IAS API has been updated).
		 *
		 * \param [in,out]	outReport	The output for parsed IAS report.
		 * \param [in,out]	outId	 	the output for report ID.
		 * \param [in,out]	outNonce 	The output for nonce in the report.
		 * \param 		  	inStr	 	The input for IAS report string.
		 */
		void ParseIasReport(sgx_ias_report_t& outReport, std::string& outId, std::string& outNonce, const std::string& inStr);

		/**
		 * \brief	This function only parses IAS's report and check its signature and nonce.
		 *
		 * \exception	Decent::RuntimeException	Parse IAS report failed, or certificate parse failed.
		 *
		 * \param [in,out]	outIasReport	The output for parsed IAS report.
		 * \param 		  	iasReportStr	The input for IAS report string.
		 * \param 		  	reportCert  	The input for IAS cert chain string that came from the header of HTTPS request.
		 * \param 		  	reportSign  	The input for IAS signature string that came from the header of HTTPS request.
		 * \param 		  	nonce			The nonce used in the quote verifying request.
		 *
		 * \return	True if it succeeds, false if it fails.
		 */
		bool ParseIasReportAndCheckSignature(sgx_ias_report_t& outIasReport,
			const std::string& iasReportStr, const std::string& reportCert, const std::string& reportSign,
			const char* nonce);

		/**
		 * \brief	Parse and verify ias report
		 *
		 * \exception	Decent::RuntimeException	Parse IAS report failed, or certificate parse failed.
		 *
		 * \tparam	Vrfier	Type of the verifier function. User provides verifier to verify the report in detail.
		 * \param [in,out]	outIasReport	The output for parsed IAS report.
		 * \param 		  	iasReportStr	The input for IAS report string.
		 * \param 		  	reportCert  	The input for IAS cert chain string that came from the header of HTTPS request.
		 * \param 		  	reportSign  	The input for IAS signature string that came from the header of HTTPS request.
		 * \param 		  	nonce			The nonce used when sending the quote verification request. (Optional, can be nullptr)
		 * \param 		  	raConfig		The RA configuration.
		 * \param 		  	vrfier			The vrfier. A lambda function that has the type of "bool FuncName(const sgx_ias_report_t&)"
		 *
		 * \return	True if it succeeds, false if it fails.
		 */
		template<typename Vrfier>
		bool ParseAndVerifyIasReport(sgx_ias_report_t& outIasReport,
			const std::string& iasReportStr, const std::string& reportCert, const std::string& reportSign,
			const char* nonce, const sgx_ra_config& raConfig, Vrfier vrfier)
		{
			const sgx_ias_report_t& iasReport = outIasReport;
			return ParseIasReportAndCheckSignature(outIasReport, iasReportStr, reportCert, reportSign, nonce) &&
				CheckIasReportStatus(iasReport, raConfig) &&
				vrfier(iasReport);
		}
	}
}
