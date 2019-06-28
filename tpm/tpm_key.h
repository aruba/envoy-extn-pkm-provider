/*----------------------------------------------------------------------
*
*   Organization: Aruba, a Hewlett Packard Enterprise company
*   Copyright [2019] Hewlett Packard Enterprise Development LP.
* 
*   Licensed under the Apache License, Version 2.0
* 
* ----------------------------------------------------------------------*/


#pragma once

#include "tss/tspi.h"
//#include <trousers/tss.h>
#include <openssl/ssl.h>

namespace Envoy {
namespace Ssl {

class TpmKey {
public:
  std::string key;
  std::string auth_type;
  std::string auth_plain;
  uint8_t auth_sha1[SHA_DIGEST_LENGTH];

  TpmKey(std::string key, std::string auth_type, std::string auth_plain, const uint8_t* auth_sha1);
  ~TpmKey();

  ASN1_OCTET_STRING* getKey(std::string marker);
  std::string toString();

private:
  ASN1_OCTET_STRING* blobstr;
};

} // namespace Ssl
} // namespace Envoy
