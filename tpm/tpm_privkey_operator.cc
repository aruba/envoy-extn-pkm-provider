/*----------------------------------------------------------------------
*
*   Organization: Aruba, a Hewlett Packard Enterprise company
*   Copyright [2019] Hewlett Packard Enterprise Development LP.
* 
*   Licensed under the Apache License, Version 2.0
* 
* ----------------------------------------------------------------------*/


#include <stdexcept>
#include <string>

#include "tss/tspi.h"
#include "envoy/server/transport_socket_config.h"
#include "tpm_privkey_operator.h"
#include "tpm_error.h"

#define NULL_HKEY 0

namespace Envoy {
namespace Ssl {

TPMPrivKeyOperatorImpl::TPMPrivKeyOperatorImpl(std::shared_ptr<TpmKey> srk) : TPMPrivKeyOperator() {
  ENVOY_LOG_MISC(debug, "TPMPrivKeyOperatorImpl::TPMPrivKeyOperatorImpl");
  loadSrk(srk);
  hKey = NULL_HKEY;
  rsa = NULL;
}

TPMPrivKeyOperatorImpl::~TPMPrivKeyOperatorImpl() {
  ENVOY_LOG_MISC(debug, "TPMPrivKeyOperatorImpl::~TPMPrivKeyOperatorImpl");
  unloadKey();
  Tspi_Context_CloseObject(hContext, hSRK);
  Tspi_Context_Close(hContext);
}

void TPMPrivKeyOperatorImpl::loadSrk(std::shared_ptr<TpmKey> srk) {

  TSS_RESULT result;
  TSS_HPOLICY srkUsagePolicy;
  UINT32 srk_authusage;

  // Initialize context
  if ((result = Tspi_Context_Create(&hContext))) {
    throw std::runtime_error("Error loading srk");
  }

  if ((result = Tspi_Context_Connect(hContext, NULL))) {
    throw std::runtime_error("Error loading srk");
  }
  // Load SRK By UUID
  if ((result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, TSS_UUID_SRK, &hSRK))) {
    Tspi_Context_Close(hContext);
    throw std::runtime_error("Error loading srk");
  }

  // Does SRK require auth?
  if ((result = Tspi_GetAttribUint32(hSRK, TSS_TSPATTRIB_KEY_INFO, TSS_TSPATTRIB_KEYINFO_AUTHUSAGE,
                                     &srk_authusage))) {
    Tspi_Context_CloseObject(hContext, hSRK);
    Tspi_Context_Close(hContext);
    throw std::runtime_error("Error loading srk");
  }

  if (srk_authusage) {
    if ((result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &srkUsagePolicy))) {
      Tspi_Context_CloseObject(hContext, hSRK);
      Tspi_Context_Close(hContext);
      throw std::runtime_error("Error loading srk");
    }

    bool auth_sha1 = srk->auth_type.compare("sha1") == 0;
    if ((result = Tspi_Policy_SetSecret(srkUsagePolicy,
                                        auth_sha1 ? TSS_SECRET_MODE_SHA1 : TSS_SECRET_MODE_PLAIN,
                                        auth_sha1 ? SHA_DIGEST_LENGTH : srk->auth_plain.size(),
                                        auth_sha1 ? srk->auth_sha1 : srk->auth_plain.c_str()))) {
      Tspi_Context_CloseObject(hContext, hSRK);
      Tspi_Context_Close(hContext);
      throw std::runtime_error("Error loading srk");
    }
  }
}

TPMPrivKeyOperator* TPMPrivKeyOperatorImpl::loadKey(std::shared_ptr<TpmKey> idkey) {
  TSS_RESULT result;
  UINT32 authusage;

  unloadKey();

  ASN1_OCTET_STRING* blobstr = idkey->getKey(std::string("TSS KEY BLOB"));

  if (blobstr == nullptr) {
    ENVOY_LOG_MISC(error, "TPMPrivKeyOperatorImpl::loadKey - invalid tss blob");
    throw std::runtime_error("Error loading key");
  }

  if ((result =
           Tspi_Context_LoadKeyByBlob(hContext, hSRK, blobstr->length, blobstr->data, &hKey))) {
    ENVOY_LOG_MISC(error, "TPMPrivKeyOperatorImpl::loadKey::Tspi_Context_LoadKeyByBlob error {}:{}",
                   result, err_string(result));
    throw std::runtime_error("Error loading key");
  }

  if ((result = Tspi_GetAttribUint32(hKey, TSS_TSPATTRIB_KEY_INFO, TSS_TSPATTRIB_KEYINFO_AUTHUSAGE,
                                     &authusage))) {
    Tspi_Context_CloseObject(hContext, hKey);
    ENVOY_LOG_MISC(error, "TPMPrivKeyOperatorImpl::loadKey::Tspi_GetAttribUint32 error {}:{}",
                   result, err_string(result));

    throw std::runtime_error("Error loading key");
  }

  if (authusage) {
    TSS_HPOLICY hPolicy;

    if ((result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE,
                                            &hPolicy))) {
      Tspi_Context_CloseObject(hContext, hKey);
      ENVOY_LOG_MISC(error, "TPMPrivKeyOperatorImpl::loadKey::Tspi_Context_CreateObject error {}:{}",
                   result, err_string(result));
      throw std::runtime_error("Error loading key");
    }

    if ((result = Tspi_Policy_AssignToObject(hPolicy, hKey))) {
      Tspi_Context_CloseObject(hContext, hKey);
      Tspi_Context_CloseObject(hContext, hPolicy);
      ENVOY_LOG_MISC(error, "TPMPrivKeyOperatorImpl::loadKey::Tspi_Policy_AssignToObject error {}:{}",
                   result, err_string(result));

      throw std::runtime_error("Error loading key");
    }

    bool auth_sha1 = idkey->auth_type.compare("sha1") == 0;
    if ((result = Tspi_Policy_SetSecret(
             hPolicy, auth_sha1 ? TSS_SECRET_MODE_SHA1 : TSS_SECRET_MODE_PLAIN,
             auth_sha1 ? SHA_DIGEST_LENGTH : idkey->auth_plain.size(),
             auth_sha1 ? idkey->auth_sha1 : idkey->auth_plain.c_str()))) {
      Tspi_Context_CloseObject(hContext, hKey);
      Tspi_Context_CloseObject(hContext, hPolicy);
      ENVOY_LOG_MISC(error, "TPMPrivKeyOperatorImpl::loadKey::Tspi_Policy_SetSecret error {}:{}",
                   result, err_string(result));
      throw std::runtime_error("Error loading key");
    }
  }
  rsa = constructRSAObject();
  if (rsa == NULL) {
    ENVOY_LOG_MISC(error, "TPMPrivKeyOperatorImpl::loadKey::Error creating rsa object");
    throw std::runtime_error("Error loading key");
  }

  return this;
}

void TPMPrivKeyOperatorImpl::unloadKey() {
  if (hKey != NULL_HKEY) {
    Tspi_Context_CloseObject(hContext, hKey);
    hKey = NULL_HKEY;
  }

  if (rsa != NULL) {
    RSA_free(rsa);
    rsa = NULL;
  }
}

RSA* TPMPrivKeyOperatorImpl::getRSA() {
  if (hKey == NULL_HKEY) {
    throw std::runtime_error("No key is loaded");
  }
  ASSERT(rsa != NULL);
  return rsa;
}

RSA* TPMPrivKeyOperatorImpl::constructRSAObject() {
  TSS_RESULT result;
  UINT32 m_size, e_size;
  BYTE *m, *e;

  if (hKey == NULL_HKEY) {
    throw std::runtime_error("No key is loaded");
  }

  if ((result = Tspi_GetAttribData(hKey, TSS_TSPATTRIB_RSAKEY_INFO,
                                   TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, &m_size, &m))) {
    ENVOY_LOG_MISC(error, "Tspi_GetAttribData (TSS_TSPATTRIB_KEYINFO_RSA_MODULUS) returned: {}:{}",
                   result, err_string(result));
    return NULL;
  }

  if ((result = Tspi_GetAttribData(hKey, TSS_TSPATTRIB_RSAKEY_INFO,
                                   TSS_TSPATTRIB_KEYINFO_RSA_EXPONENT, &e_size, &e))) {
    ENVOY_LOG_MISC(error, "Tspi_GetAttribData (TSS_TSPATTRIB_KEYINFO_RSA_EXPONENT) returned: {}:{}",
                   result, err_string(result));
    return NULL;
  }

  RSA* rsa = RSA_new();
  rsa->e = BN_bin2bn(e, e_size, rsa->e);
  rsa->n = BN_bin2bn(m, m_size, rsa->n);

  return rsa;
}

int TPMPrivKeyOperatorImpl::encrypt(const uint8_t* in, size_t in_len, uint8_t* out,
                                    size_t* out_len) {
  ENVOY_LOG_MISC(debug, "TPMPrivKeyOperatorImpl::encrypt");
  TSS_RESULT result;
  TSS_HOBJECT hHash;
  if ((result =
           Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_HASH, TSS_HASH_OTHER, &hHash))) {
    throw std::runtime_error("Error encrypting");
  }

  // TODO: validate the length of input against the hash alg's standard length

  if ((result = Tspi_Hash_SetHashValue(hHash, in_len, (BYTE*)in))) {
    Tspi_Context_CloseObject(hContext, hHash);
    ENVOY_LOG_MISC(error, "TPMPrivKeyOperatorImpl::encrypt::Tspi_Hash_SetHashValue failed::{}::{}",
                   result, err_string(result));
    throw std::runtime_error("Error encrypting");
  }

  UINT32 sig_len;
  BYTE* sig;
  if ((result = Tspi_Hash_Sign(hHash, hKey, &sig_len, &sig))) {
    Tspi_Context_CloseObject(hContext, hHash);
    ENVOY_LOG_MISC(error, "TPMPrivKeyOperatorImpl::encrypt::Tspi_Hash_Sign failed::{}::{}",
		    result, err_string(result));
    throw std::runtime_error("Error encrypting");
  }

  memcpy(out, sig, sig_len);
  *out_len = sig_len;

  Tspi_Context_FreeMemory(hContext, sig);
  Tspi_Context_CloseObject(hContext, hHash);

  return 0;
}

int TPMPrivKeyOperatorImpl::decrypt(const uint8_t* in, size_t in_len, uint8_t* out,
                                    size_t* out_len) {
  throw std::runtime_error("Not implemented");
}

} // namespace Ssl
} // namespace Envoy
