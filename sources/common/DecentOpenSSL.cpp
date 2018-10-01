#include "DecentOpenSSL.h"

#include <sgx_trts.h>

#include <openssl/x509.h>
#include <openssl/ssl.h>

#include "OpenSSLInitializer.h"

static long GetDecentSerialNumber()
{
	long ret = 0;
	return sgx_read_rand(reinterpret_cast<uint8_t*>(&ret), sizeof(ret)) == SGX_SUCCESS ? ret : 0;
}

DecentServerX509::DecentServerX509(const std::string & pemStr) :
	X509Wrapper(pemStr),
	k_platformType(ParsePlatformType()),
	k_selfRaReport(ParseSelfRaReport())
{
}

DecentServerX509::DecentServerX509(const ECKeyPair & prvKey, const std::string& enclaveHash, const std::string& platformType, const std::string& selfRaReport) :
	X509Wrapper(prvKey, 
		LONG_MAX, 
		GetDecentSerialNumber(), 
		X509NameWrapper(std::map<std::string, std::string>({
			std::pair<std::string, std::string>("CN", enclaveHash),
		})), 
		std::map<int, std::string>{
			std::pair<int, std::string>(NID_basic_constraints, "critical,CA:TRUE"),
			std::pair<int, std::string>(NID_key_usage, "critical,nonRepudiation,digitalSignature,keyAgreement,keyCertSign,cRLSign"),
			std::pair<int, std::string>(NID_ext_key_usage, "serverAuth,clientAuth"),
			std::pair<int, std::string>(NID_subject_key_identifier, "hash"),
			std::pair<int, std::string>(NID_netscape_cert_type, "sslCA,client,server"),
			std::pair<int, std::string>(DecentOpenSSLInitializer::Initialize().GetPlatformTypeNID(), "critical," + platformType),
			std::pair<int, std::string>(DecentOpenSSLInitializer::Initialize().GetSelfRAReportNID(), "critical," + selfRaReport),
		}),
	k_platformType(platformType),
	k_selfRaReport(selfRaReport)
{
}

const std::string & DecentServerX509::GetPlatformType() const
{
	return k_platformType;
}

const std::string & DecentServerX509::GetSelfRaReport() const
{
	return k_selfRaReport;
}

const std::string DecentServerX509::ParsePlatformType() const
{
	return ParseExtensionString(DecentOpenSSLInitializer::Initialize().GetPlatformTypeNID());
}

const std::string DecentServerX509::ParseSelfRaReport() const
{
	return ParseExtensionString(DecentOpenSSLInitializer::Initialize().GetSelfRAReportNID());
}

DecentAppX509::DecentAppX509(const std::string & pemStr) :
	X509Wrapper(pemStr),
	k_platformType(ParsePlatformType()),
	k_appId(ParseAppId())
{
}

DecentAppX509::DecentAppX509(const ECKeyPublic & pubKey, const DecentServerX509& caCert, const ECKeyPair & serverPrvKey, const std::string & enclaveHash, const std::string & platformType, const std::string & appId) :
	X509Wrapper(caCert, serverPrvKey, pubKey, 
		LONG_MAX,
		GetDecentSerialNumber(),
		X509NameWrapper(std::map<std::string, std::string>({
			std::pair<std::string, std::string>("CN", enclaveHash),
			})),
			std::map<int, std::string>{
	std::pair<int, std::string>(NID_basic_constraints, "critical,CA:TRUE"),
		std::pair<int, std::string>(NID_key_usage, "critical,nonRepudiation,digitalSignature,keyAgreement,keyCertSign,cRLSign"),
		std::pair<int, std::string>(NID_ext_key_usage, "serverAuth,clientAuth"),
		std::pair<int, std::string>(NID_subject_key_identifier, "hash"),
		std::pair<int, std::string>(NID_netscape_cert_type, "sslCA,client,server"),
		std::pair<int, std::string>(DecentOpenSSLInitializer::Initialize().GetPlatformTypeNID(), "critical," + platformType),
		std::pair<int, std::string>(DecentOpenSSLInitializer::Initialize().GetLocalAttestationIdNID(), "critical," + appId),
	}),
	k_platformType(platformType),
	k_appId(appId)
{
}

const std::string & DecentAppX509::GetPlatformType() const
{
	return k_platformType;
}

const std::string & DecentAppX509::GetAppId() const
{
	return k_appId;
}

const std::string DecentAppX509::ParsePlatformType() const
{
	return ParseExtensionString(DecentOpenSSLInitializer::Initialize().GetPlatformTypeNID());
}

const std::string DecentAppX509::ParseAppId() const
{
	return ParseExtensionString(DecentOpenSSLInitializer::Initialize().GetLocalAttestationIdNID());
}

//DecentTlsCtx & DecentTlsCtx::GetInst()
//{
//	static DecentTlsCtx instance;
//	return instance;
//}
//
//DecentTlsCtx::DecentTlsCtx() :
//	SSLCTXWrapper(SSL_CTX_new(TLSv1_2_method()), true)
//{
//	if (!m_ptr)
//	{
//		return;
//	}
//
//	if (
//		!SSL_CTX_set_cipher_list(m_ptr, "ECDHE-ECDSA-AES128-GCM-SHA256") ||
//		!SSL_CTX_set_min_proto_version(m_ptr, TLS1_2_VERSION)
//		)
//	{
//		this->~DecentTlsCtx();
//		return;
//	}
//
//	SSL_CTX_set_verify_depth(m_ptr, 0);
//}
