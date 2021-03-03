/**
 * \file	RaReport.h.
 *
 * \brief	Declares the Self-RA Report related stuffs.
 * 			This header is not used for anything specific to SGX. Thus, we don't include SGX related headers in here.
 */
#pragma once

#include <cstdint>

#include <string>
#include <vector>

#include <mbedTLScpp/Hash.hpp>

#include "../structs.h"
#include "../Exceptions.h"

typedef struct _sgx_ias_report_t sgx_ias_report_t;

namespace Decent
{
	namespace Ra
	{
		namespace RaReport
		{
			constexpr char const sk_LabelRoot[] = "DecentSelfRAReport";

			constexpr char const sk_LabelIasReport[] = "IASReport";
			constexpr char const sk_LabelIasSign[] = "IASSignature";
			constexpr char const sk_LabelIasCertChain[] = "IASCertChain";
			constexpr char const sk_LabelOriRepData[] = "OriReportData";

			constexpr char const sk_ValueReportTypeSgx[] = "SGX";

			/**
			 * \brief	Decent RA's default RA configuration for SGX platform. These SGX related stuffs may
			 * 			be used for Self-RA report verification in other platform.
			 */
			constexpr sgx_ra_config sk_sgxDecentRaConfig =
			{
				SGX_QUOTE_LINKABLE_SIGNATURE,
				SGX_DEFAULT_AES_CMAC_KDF_ID,
				0, //Disenabled PSE
				1, //Allow out-of-date enclave
				1, //Allow configuration needed enclave
				1  //Allow out-of-date PSE
			};

			/**
			 * \brief	Decent report data verifier used to verify the
			 *          `report data` field stored inside the RA report.
			 *
			 * \param	pubSignKey	The public sign key.
			 * \param	initData  	Initial report data (the initial report
			 *                      data specified by platform's standard,
			 *                      before Decent customized modification).
			 * \param	expected  	The expected report data.
			 *
			 * \return	True if it succeeds, false if it fails.
			 */
			template<typename _InitRdDataCtnType, typename _ExpRdDataCtnType>
			bool DecentReportDataVerifier(const std::string& pubSignKey,
				const mbedTLScpp::ContCtnReadOnlyRef<_InitRdDataCtnType, false>& initialRp,
				const mbedTLScpp::ContCtnReadOnlyRef<_ExpRdDataCtnType, false>& expectedRp)
			{
				using namespace mbedTLScpp;
				constexpr HashType hashT = HashType::SHA256;
				constexpr size_t hashSize = GetHashByteSize(hashT);

				if (expectedRp.GetRegionSize() < hashSize)
				{
					throw RuntimeException("Ra::DecentReportDataVerifier - The size of expected report data is too small.");
				}

				Hash<hashT> calcHash =
					Hasher<hashT>().Calc(
						CtnByteRgR<0, hashSize>(initialRp),
						CtnFullR(pubSignKey)
					);

				return std::equal(expectedRp.BeginBytePtr(), expectedRp.BeginBytePtr() + hashSize, calcHash.m_data.begin()) &&
					std::all_of(expectedRp.BeginBytePtr() + hashSize, expectedRp.EndBytePtr(),
						[](const uint8_t& x) { return x == 0; });
			}

			/**
			 * \brief	Process the Decent Self-RA report. Verifying if the report is valid or not.
			 *
			 * \exception	Decent::RuntimeException	Unrecognized enclave platform. Or parse error from
			 * 											underlying calls.
			 *
			 * \param 		  	platformType	Type of the enclave platform.
			 * \param 		  	pubKeyPem   	The public key in PEM.
			 * \param 		  	raReport		The RA report.
			 * \param [in,out]	outHashStr  	The out enclave's hash string.
			 * \param [in,out]	outTimestamp	The out timestamp.
			 *
			 * \return	True if it is valid, false if not.
			 */
			bool ProcessSelfRaReport(const std::string& platformType,
				const std::string& pubKeyPem, const std::string& raReport,
				std::string& outHashStr, report_timestamp_t& outTimestamp);

			/**
			 * \brief	Process the Decent Self-RA report produced in SGX platform. Verifying if the report
			 * 			is valid or not.
			 *
			 * \exception	Decent::RuntimeException	Unrecognized enclave platform. Or parse error from
			 * 											underlying calls.
			 *
			 * \param 		  	pubKeyPem   	The public key in PEM.
			 * \param 		  	raReport		The RA report.
			 * \param [in,out]	outIasReport	The output parsed IAS report.
			 *
			 * \return	True if it is valid, false if not.
			 */
			bool ProcessSgxSelfRaReport(const std::string& pubKeyPem, const std::string& raReport, sgx_ias_report_t& outIasReport);
		}
	}
}
