/*----------------------------------------------------------------------
*
*   Organization: Aruba, a Hewlett Packard Enterprise company
*   Copyright [2019] Hewlett Packard Enterprise Development LP.
* 
*   Licensed under the Apache License, Version 2.0
* 
* ----------------------------------------------------------------------*/


#include <string>
#include <memory.h>
#include <sstream>

#include "tpm_key.h"
#include "util.h"

namespace Envoy {
namespace Ssl {

TpmKey::TpmKey(std::string key, std::string auth_type, std::string auth_plain,
               const uint8_t* auth_sha1)
    : key(key), auth_type(auth_type), auth_plain(auth_plain), blobstr(nullptr) {
  memcpy(this->auth_sha1, auth_sha1, SHA_DIGEST_LENGTH);
}

TpmKey::~TpmKey() {
  if (blobstr != nullptr) {
    ASN1_OCTET_STRING_free(blobstr);
  }
}

ASN1_OCTET_STRING* TpmKey::getKey(std::string marker) {

  if (blobstr != nullptr) {
    return blobstr;
  }

  bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(const_cast<char*>(key.c_str()), key.size()));

  blobstr =
      PEM_ASN1_read_bio((void*)d2i_ASN1_OCTET_STRING, marker.c_str(), bio.get(), NULL, NULL, NULL);

  if (blobstr == nullptr) {
    return nullptr;
  }
  return blobstr;
}

std::string TpmKey::toString() {
  std::ostringstream ret;
  ret << auth_type << ": "
      << (auth_type.compare("sha1") == 0 ? binary2hex(auth_sha1, SHA_DIGEST_LENGTH) : auth_plain);
  return ret.str();
}
} // namespace Ssl
} // namespace Envoy
