#pragma once

#include <string>

typedef struct ec_key_st EC_KEY;

std::string ECKeyPubGetPEMStr(const EC_KEY* inKey);

EC_KEY* ECKeyPubFromPEMStr(const std::string& inPem);
