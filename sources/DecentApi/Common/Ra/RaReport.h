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

#include "../CommonType.h"
#include "../structs.h"

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
			 * \brief	These SGX related stuffs may be used for Self-RA report verification in other
			 * 			platform.
			 */
			constexpr sgx_ra_config sk_sgxDecentRaConfig = 
			{
				SGX_QUOTE_LINKABLE_SIGNATURE,
				SGX_DEFAULT_AES_CMAC_KDF_ID,
#ifndef SIMULATING_ENCLAVE
				1, //Enable PSE
#else
				0,
#endif 
				1, //Allow out-of-date enclave
				1, //Allow configuration needed enclave
				1 //Allow out-of-date PSE
			};

			bool DecentReportDataVerifier(const std::string& pubSignKey, const uint8_t* initData, const uint8_t* expected, const size_t size);

			bool ProcessSelfRaReport(const std::string& platformType, const std::string& pubKeyPem, const std::string& raReport, std::string& outHashStr, TimeStamp& outTimestamp);

			bool ProcessSgxSelfRaReport(const std::string& pubKeyPem, const std::string& raReport, sgx_ias_report_t& outIasReport);
		}
	}
}
