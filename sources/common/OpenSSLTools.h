#pragma once

#include <vector>
#include <string>

typedef struct ec_key_st EC_KEY;
typedef struct x509_st X509;

std::string ECKeyPubGetPEMStr(const EC_KEY* inKey);

EC_KEY* ECKeyPubFromPEMStr(const std::string& inPem);

void LoadX509CertsFromStr(std::vector<X509*>& outCerts, const std::string& certStr);

bool VerifyIasReportCert(X509* root, const std::vector<X509*>& certsInHeader);

bool VerifyIasReportSignature(const std::string& data, std::vector<uint8_t> signature, X509* cert);

void FreeX509Cert(X509** cert);

void FreeX509Cert(std::vector<X509*>& certs);
