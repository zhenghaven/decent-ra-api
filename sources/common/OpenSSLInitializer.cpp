#include "OpenSSLInitializer.h"

#include <openssl/ssl.h>
#include <openssl/objects.h>
#include <openssl/x509v3.h>

const OpenSSLInitializer & OpenSSLInitializer::Initialize()
{
	static const OpenSSLInitializer inst;
	return inst;
}

OpenSSLInitializer::OpenSSLInitializer()
{
#ifndef ENCLAVE_CODE
	SSL_library_init();
#endif // !ENCLAVE_CODE
}

OpenSSLInitializer::~OpenSSLInitializer()
{
}

DecentOpenSSLInitializer::DecentOpenSSLInitializer() :
	k_baseInit(OpenSSLInitializer::Initialize()),
	k_selfRAReportNID(OBJ_create("2.25.210204819921761154072721866869208165061", "SelfRaReport", "Decent Self Remote Attestation Report")),
	k_laIdNID(OBJ_create("2.25.128165920542469106824459777090692906263", "LaId", "Decent Local Attestation Identity")),
	k_platformTypeNID(OBJ_create("2.25.294010332531314719175946865483017979201", "PlatformType", "Decent Enclave Platform Type"))
{
	X509V3_EXT_add_alias(k_selfRAReportNID, NID_netscape_comment);
	X509V3_EXT_add_alias(k_laIdNID, NID_netscape_comment);
	X509V3_EXT_add_alias(k_platformTypeNID, NID_netscape_comment);
}

const DecentOpenSSLInitializer & DecentOpenSSLInitializer::Initialize()
{
	static const DecentOpenSSLInitializer inst;
	return inst;
}

DecentOpenSSLInitializer::~DecentOpenSSLInitializer()
{
}

const OpenSSLInitializer & DecentOpenSSLInitializer::GetOpenSSLInitializer() const
{
	return k_baseInit;
}

int DecentOpenSSLInitializer::GetSelfRAReportNID() const
{
	return k_selfRAReportNID;
}

int DecentOpenSSLInitializer::GetLocalAttestationIdNID() const
{
	return k_laIdNID;
}

int DecentOpenSSLInitializer::GetPlatformTypeNID() const
{
	return k_platformTypeNID;
}
