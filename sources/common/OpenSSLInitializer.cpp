#include "OpenSSLInitializer.h"

#include <openssl/ssl.h>
#include <openssl/objects.h>

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
	k_laIdNID(OBJ_create("2.25.128165920542469106824459777090692906263", "LaId", "Decent Local Attestation Identity"))
{
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
