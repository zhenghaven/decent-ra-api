#pragma once

#include <vector>
#include <string>
#include <map>

#include "GeneralKeyTypes.h"

typedef struct ec_key_st EC_KEY;
typedef struct evp_pkey_st EVP_PKEY;
typedef struct bio_st BIO;
typedef struct x509_st X509;
typedef struct X509_req_st X509_REQ;
typedef struct X509_name_st X509_NAME;
typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_st SSL;

void LoadX509CertsFromStr(std::vector<X509*>& outCerts, const std::string& certStr);

bool VerifyIasReportCert(X509* root, const std::vector<X509*>& certsInHeader);

bool VerifyIasReportSignature(const std::string& data, std::vector<uint8_t> signature, X509* cert);

void FreeX509Cert(X509** cert);

void FreeX509Cert(std::vector<X509*>& certs);
