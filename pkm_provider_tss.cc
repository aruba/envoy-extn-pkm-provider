/*----------------------------------------------------------------------
*
*   Organization: Aruba, a Hewlett Packard Enterprise company
*   Copyright [2019] Hewlett Packard Enterprise Development LP.
* 
*   Licensed under the Apache License, Version 2.0
* 
* ----------------------------------------------------------------------*/


#include "envoy/ssl/private_key/private_key_config.h"
#include "envoy/server/transport_socket_config.h"
#include "tss/tspi.h"

#include "pkm_provider_tss.h"
#include "tpm/tpm_privkey_operator.h"
#include "util.h"

namespace Envoy {
namespace Ssl {

// initialize static members
int TssPKMPrivateKeyMethodProvider::ssl_rsa_connection_index = -1;
std::shared_ptr<SSL_PRIVATE_KEY_METHOD> TssPKMPrivateKeyMethodProvider::method_ = NULL;

static RSA* get_rsa_object(TSS_HKEY hKey) {
  TSS_RESULT result;
  UINT32 m_size, e_size;
  BYTE *m, *e;

  if (result = Tspi_GetAttribData(hKey, TSS_TSPATTRIB_RSAKEY_INFO,
                                  TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, &m_size, &m)) {
    ENVOY_LOG_MISC(error, "Tspi_GetAttribData (TSS_TSPATTRIB_KEYINFO_RSA_MODULUS) returned: {}",
                   result);
    return NULL;
  }

  if (result = Tspi_GetAttribData(hKey, TSS_TSPATTRIB_RSAKEY_INFO,
                                  TSS_TSPATTRIB_KEYINFO_RSA_EXPONENT, &e_size, &e)) {
    ENVOY_LOG_MISC(error, "Tspi_GetAttribData (TSS_TSPATTRIB_KEYINFO_RSA_EXPONENT) returned: {}",
                   result);
    return NULL;
  }

  RSA* rsa = RSA_new();
  rsa->e = BN_bin2bn(e, e_size, rsa->e);
  rsa->n = BN_bin2bn(m, m_size, rsa->n);

  return rsa;
}

static int compute_digest(RSA* rsa, const uint8_t* in, size_t in_len, uint16_t signature_algorithm,
                          uint8_t** msg, size_t* msg_len, int* is_alloced) {

  uint8_t hash[EVP_MAX_MD_SIZE];
  unsigned int hash_len = 0;
  bssl::ScopedEVP_MD_CTX ctx;

  const EVP_MD* md = SSL_get_signature_algorithm_digest(signature_algorithm);

  if (!EVP_DigestInit_ex(ctx.get(), md, nullptr) || !EVP_DigestUpdate(ctx.get(), in, in_len) ||
      !EVP_DigestFinal_ex(ctx.get(), hash, &hash_len)) {
    return ssl_private_key_failure;
  }

  // Addd RSA padding to the the hash. Supported types are PSS and PKCS1.
  if (SSL_is_signature_algorithm_rsa_pss(signature_algorithm)) {
    *msg_len = RSA_size(rsa);
    *msg = static_cast<uint8_t*>(OPENSSL_malloc(*msg_len));
    if (!*msg) {
      return 1;
    }

    *is_alloced = 1;
    if (!RSA_padding_add_PKCS1_PSS_mgf1(rsa, *msg, hash, md, NULL, -1)) {
      return 1;
    }

  } else {
    if (!RSA_add_pkcs1_prefix(msg, msg_len, is_alloced, EVP_MD_type(md), hash, hash_len)) {
      return 1;
    }
  }

  return 0;
}
static ssl_private_key_result_t PrivateKeySign(SSL* ssl, uint8_t* out, size_t* out_len,
                                               size_t max_out, uint16_t signature_algorithm,
                                               const uint8_t* in, size_t in_len) {
  RSA* rsa;
  uint8_t* msg;
  size_t msg_len;
  int is_alloced;

  TssPKMPrivateKeyConnection* conn = static_cast<TssPKMPrivateKeyConnection*>(
      SSL_get_ex_data(ssl, TssPKMPrivateKeyMethodProvider::ssl_rsa_connection_index));

  if (!conn) {
    return ssl_private_key_failure;
  }

  std::shared_ptr<TpmKey> srk = conn->getSrk();
  std::shared_ptr<TpmKey> idkey = conn->getIdKey();
    ENVOY_LOG_MISC(debug, "SRK: {}", srk->toString());
    ENVOY_LOG_MISC(debug, "idkey: {}", idkey->toString());
  try {
    std::unique_ptr<TPMPrivKeyOperatorImpl> tpmPrivKeyOperator =
        std::make_unique<TPMPrivKeyOperatorImpl>(srk);
     
    tpmPrivKeyOperator->loadKey(idkey);
    rsa = tpmPrivKeyOperator->getRSA();

    if (compute_digest(rsa, in, in_len, signature_algorithm, &msg, &msg_len, &is_alloced)) {
      ENVOY_LOG_MISC(error, "Error computing digest");
      return ssl_private_key_failure;
    }
    ENVOY_LOG_MISC(debug, "digest: {}", binary2hex(msg, msg_len).c_str());
    tpmPrivKeyOperator->encrypt(msg, msg_len, out, out_len);
    
  } catch (std::exception& e) {
     ENVOY_LOG_MISC(error, "Exception {}", e.what());
     return ssl_private_key_failure;
  }

  if (is_alloced) {
    OPENSSL_free(msg);
  }
  return ssl_private_key_success;
}

static ssl_private_key_result_t PrivateKeySign1(SSL* ssl, uint8_t* out, size_t* out_len,
                                                size_t max_out, uint16_t signature_algorithm,
                                                const uint8_t* in, size_t in_len) {

  (void)out;
  (void)out_len;
  (void)max_out;

  (void)signature_algorithm;
  (void)in;
  (void)in_len;

  bssl::ScopedEVP_MD_CTX ctx;

  TSS_HCONTEXT hContext;
  TSS_HKEY hSRK;
  TSS_HKEY hKey;
  TSS_RESULT result;
  TSS_HOBJECT hHash;

  TSS_UUID SRK_UUID = TSS_UUID_SRK;
  TSS_HPOLICY srkUsagePolicy;
  UINT32 srk_authusage;

  // Determine the hash.
  // unsigned char hash[EVP_MAX_MD_SIZE];
  // unsigned int hash_len = 0;

  TssPKMPrivateKeyConnection* conn = static_cast<TssPKMPrivateKeyConnection*>(
      SSL_get_ex_data(ssl, TssPKMPrivateKeyMethodProvider::ssl_rsa_connection_index));

  if (!conn) {
    return ssl_private_key_failure;
  }

  std::shared_ptr<TpmKey> srk = conn->getSrk();
  std::shared_ptr<TpmKey> idkey = conn->getIdKey();

  ASN1_OCTET_STRING* blobstr = idkey->getKey("TSS KEY BLOB");

  if (blobstr == nullptr) {
    return ssl_private_key_failure;
  }

  // const EVP_MD *md = SSL_get_signature_algorithm_digest(signature_algorithm);

  /*
  BYTE oid_sha265[19] = {
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
  0x00, 0x04, 0x20
  };


  switch (EVP_MD_type(md)) {
  case NID_sha256:
    break;
  default:
    ENVOY_LOG_MISC(error, "AsyncPrivateKeySign -- unknown digest");
    return ssl_private_key_failure;

  }



  memcpy(hash, oid_sha265, 19);

  */

  /*
  if (!EVP_DigestInit_ex(ctx.get(), md, nullptr) || !EVP_DigestUpdate(ctx.get(), in, in_len) ||
      !EVP_DigestFinal_ex(ctx.get(), hash, &hash_len)) {
    return ssl_private_key_failure;
  }
  //hash_len += 19;

  uint8_t* msg;
  size_t msg_len;
  int prefix_allocated = 0;

  // Addd RSA padding to the the hash. Supported types are PSS and PKCS1.
  if (SSL_is_signature_algorithm_rsa_pss(signature_algorithm)) {
    msg_len = RSA_size(rsa);
    msg = static_cast<uint8_t*>(OPENSSL_malloc(msg_len));
    if (!msg) {
      goto error;
    }

    prefix_allocated = 1;
    if (!RSA_padding_add_PKCS1_PSS_mgf1(rsa, msg, hash, md, NULL, -1)) {
      return ssl_private_key_failure;
    }

  } else {
    if (!RSA_add_pkcs1_prefix(&msg, &msg_len, &prefix_allocated, EVP_MD_type(md), hash, hash_len)) {
      return ssl_private_key_failure;
    }

  }

  */

  // Initialize context
  if ((result = Tspi_Context_Create(&hContext))) {
    return ssl_private_key_failure;
  }

  // XXX allow dest to be specified through pre commands
  if ((result = Tspi_Context_Connect(hContext, NULL))) {
    return ssl_private_key_failure;
  }
  // Load SRK Key By UUID
  if ((result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK))) {
    Tspi_Context_Close(hContext);
    return ssl_private_key_failure;
  }

  // Does SRK require auth?
  if ((result = Tspi_GetAttribUint32(hSRK, TSS_TSPATTRIB_KEY_INFO, TSS_TSPATTRIB_KEYINFO_AUTHUSAGE,
                                     &srk_authusage))) {
    Tspi_Context_CloseObject(hContext, hSRK);
    Tspi_Context_Close(hContext);
    return ssl_private_key_failure;
  }

  if (srk_authusage) {
    char* authdata = reinterpret_cast<char*>(calloc(1, 128));

    if (!authdata) {
      fprintf(stderr, "calloc failed.\n");
      Tspi_Context_Close(hContext);
      return ssl_private_key_failure;
    }

    if ((result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &srkUsagePolicy))) {
      Tspi_Context_CloseObject(hContext, hSRK);
      Tspi_Context_Close(hContext);
      free(authdata);
      return ssl_private_key_failure;
    }

    // static BYTE srkAuthBytes[20] = {0xcd, 0xf, 0xa8, 0xeb, 0x44, 0xba, 0x9f, 0xa1, 0xe1, 0xec,
    // 0x9f, 0xdf, 0x8f, 0x2c, 0x5b, 0x61, 0xb1, 0x1, 0x84, 0xa7 };

    if ((result = Tspi_Policy_SetSecret(
             srkUsagePolicy,
             srk->auth_type == "sha1" ? TSS_SECRET_MODE_SHA1 : TSS_SECRET_MODE_PLAIN,
             srk->auth_type == "sha1" ? SHA_DIGEST_LENGTH : srk->auth_plain.size(),
             srk->auth_type == "sha1" ? srk->auth_sha1 : srk->auth_plain.c_str()))) {
      // print_error("Tspi_Policy_SetSecret", result);
      free(authdata);
      Tspi_Context_CloseObject(hContext, hSRK);
      Tspi_Context_Close(hContext);
      return ssl_private_key_failure;
    }

    free(authdata);
  }

ENVOY_LOG_MISC(debug, "Calling Tspi_Context_LoadKeyByBlob");
  if ((result =
           Tspi_Context_LoadKeyByBlob(hContext, hSRK, blobstr->length, blobstr->data, &hKey))) {
    // print_error("Tspi_Context_LoadKeyByBlob", result);
    // printf("load key by blob failed: %d, %d, %d\n",  result, TPM_F_TPM_ENGINE_LOAD_KEY,
    //       TPM_R_REQUEST_FAILED);
    // TSSerr(TPM_F_TPM_ENGINE_LOAD_KEY,
    //       TPM_R_REQUEST_FAILED);
    ENVOY_LOG_MISC(error, "Tspi_Context_LoadKeyByBlob error {}", result);
    return ssl_private_key_failure;
  }
ENVOY_LOG_MISC(debug, "Calling Tspi_Context_LoadKeyByBlob done");
  UINT32 authusage;
  if ((result = Tspi_GetAttribUint32(hKey, TSS_TSPATTRIB_KEY_INFO, TSS_TSPATTRIB_KEYINFO_AUTHUSAGE,
                                     &authusage))) {
    Tspi_Context_CloseObject(hContext, hKey);
    // TSSerr(TPM_F_TPM_ENGINE_LOAD_KEY,
    //       TPM_R_REQUEST_FAILED);
    ENVOY_LOG_MISC(error, "Tspi_GetAttribUint32 error {}", result);

    return ssl_private_key_failure;
  }

  if (authusage) {
    TSS_HPOLICY hPolicy;

    // URK1
    // BYTE auth[20] = {0x7, 0x18, 0xe5, 0x5d, 0xb6, 0xf, 0x74, 0xe8, 0x9, 0xb8, 0x4c, 0xa9, 0x3a,
    // 0xc1, 0x4d, 0xc3, 0x2, 0xe8, 0x83, 0xb3 };

    // URK2
    // BYTE auth[20] = {0xfc, 0xdf, 0xab, 0xb, 0xa2, 0x27, 0x10, 0x64, 0xdf, 0x65, 0x38, 0x9f, 0x3,
    // 0x72, 0xf, 0xfc, 0xfd, 0x18, 0x5f, 0x55};

    if ((result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE,
                                            &hPolicy))) {
      Tspi_Context_CloseObject(hContext, hKey);
      // TSSerr(TPM_F_TPM_ENGINE_LOAD_KEY, TPM_R_REQUEST_FAILED);
      ENVOY_LOG_MISC(error, "Tspi_Context_CreateObject error {}", result);
      return ssl_private_key_failure;
    }

    if ((result = Tspi_Policy_AssignToObject(hPolicy, hKey))) {
      Tspi_Context_CloseObject(hContext, hKey);
      Tspi_Context_CloseObject(hContext, hPolicy);
      // TSSerr(TPM_F_TPM_ENGINE_LOAD_KEY, TPM_R_REQUEST_FAILED);
      ENVOY_LOG_MISC(error, "Tspi_Policy_AssignToObject error {}", result);

      return ssl_private_key_failure;
    }

    if ((result = Tspi_Policy_SetSecret(
             hPolicy, idkey->auth_type == "sha1" ? TSS_SECRET_MODE_SHA1 : TSS_SECRET_MODE_PLAIN,
             idkey->auth_type == "sha1" ? SHA_DIGEST_LENGTH : idkey->auth_plain.size(),
             idkey->auth_type == "sha1" ? idkey->auth_sha1 : idkey->auth_plain.c_str()))) {
      Tspi_Context_CloseObject(hContext, hKey);
      Tspi_Context_CloseObject(hContext, hPolicy);
      // TSSerr(TPM_F_TPM_ENGINE_LOAD_KEY, TPM_R_REQUEST_FAILED);
      ENVOY_LOG_MISC(error, "Tspi_Policy_SetSecret error {}", result);
      return ssl_private_key_failure;
    }
  }
  ENVOY_LOG_MISC(debug, "Calling hKey auth done");

  RSA* rsa = get_rsa_object(hKey);
  if (rsa == NULL) {
    ENVOY_LOG_MISC(error, "Error creating rsa object");
    return ssl_private_key_failure;
  }

  uint8_t* msg;
  size_t msg_len;
  int is_alloced;
  if (compute_digest(rsa, in, in_len, signature_algorithm, &msg, &msg_len, &is_alloced)) {
    ENVOY_LOG_MISC(error, "Error computing digest");
    return ssl_private_key_failure;
  }

    ENVOY_LOG_MISC(debug, "digest: {}", binary2hex(msg, msg_len).c_str());

  // Set the hash, that will be signed in the next step

  if ((result =
           Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_HASH, TSS_HASH_OTHER, &hHash))) {
    // TSSerr(TPM_F_TPM_RSA_PRIV_ENC, TPM_R_REQUEST_FAILED);
    return ssl_private_key_failure;
  }

  // TODO: validate the length of input against the hash alg's standard length

  if ((result = Tspi_Hash_SetHashValue(hHash, msg_len, (BYTE*)msg))) {
    // TSSerr(TPM_F_TPM_RSA_PRIV_ENC, TPM_R_REQUEST_FAILED);
    return ssl_private_key_failure;
  }

  printf("Now sign the hash\n");
  UINT32 sig_len;
  BYTE* sig;
  if ((result = Tspi_Hash_Sign(hHash, hKey, &sig_len, &sig))) {
    // TSSerr(TPM_F_TPM_RSA_PRIV_ENC, TPM_R_REQUEST_FAILED);
    ENVOY_LOG_MISC(error, "AsyncPrivateKeySign -- signing failed - {}", result);

    // printf("Signing failed: 0x%x -- (%s)\n", result, Trspi_Error_String(result));
    return ssl_private_key_failure;
  }

  printf("Signing complete length %d\n", sig_len);

  // hexdump(sig, sig_len);
  memcpy(out, sig, sig_len);
  *out_len = sig_len;
  ENVOY_LOG_MISC(error, "AsyncPrivateKeySign -- signature length  - {}", sig_len);
  Tspi_Context_FreeMemory(hContext, sig);
  ENVOY_LOG_MISC(error, "AsyncPrivateKeySign -- returning success");

  printf("AsyncPrivateKeySign - returning; sign length %d\n", sig_len);

  if (is_alloced) {
    OPENSSL_free(msg);
  }

  return ssl_private_key_success;
}

static ssl_private_key_result_t PrivateKeyDecrypt(SSL* /* ssl */, uint8_t* /* out */,
                                                  size_t* /* out_len */, size_t /* max_out */,
                                                  const uint8_t* /* in */, size_t /* in_len */) {
  // Not implemented
  return ssl_private_key_failure;
}

static ssl_private_key_result_t PrivateKeyComplete(SSL* ssl, uint8_t* out, size_t* out_len,
                                                   size_t max_out) {

  TssPKMPrivateKeyConnection* conn = static_cast<TssPKMPrivateKeyConnection*>(
      SSL_get_ex_data(ssl, TssPKMPrivateKeyMethodProvider::ssl_rsa_connection_index));

  if (!conn) {
    return ssl_private_key_failure;
  }

  if (conn->buf_len > max_out) {
    OPENSSL_free(conn->buf);
    return ssl_private_key_failure;
  }

  memcpy(out, conn->buf, conn->buf_len);
  *out_len = conn->buf_len;
  OPENSSL_free(conn->buf);

  SSL_set_ex_data(ssl, TssPKMPrivateKeyMethodProvider::ssl_rsa_connection_index, nullptr);

  return ssl_private_key_success;
}

TssPKMPrivateKeyConnection::TssPKMPrivateKeyConnection(SSL* ssl, std::shared_ptr<TpmKey> srk,
                                                       std::shared_ptr<TpmKey> idkey)
    : srk(move(srk)), idkey(move(idkey)) {
  SSL_set_ex_data(ssl, TssPKMPrivateKeyMethodProvider::ssl_rsa_connection_index, this);
}

Ssl::PrivateKeyConnectionPtr TssPKMPrivateKeyMethodProvider::getPrivateKeyConnection(
    SSL* ssl, Ssl::PrivateKeyConnectionCallbacks& cb, Event::Dispatcher& dispatcher) {

  (void)cb;
  (void)dispatcher;

  return std::make_unique<TssPKMPrivateKeyConnection>(ssl, srk, idkey);
}

TssPKMPrivateKeyMethodProvider::TssPKMPrivateKeyMethodProvider(
    const ProtobufWkt::Struct& config,
    Server::Configuration::TransportSocketFactoryContext& factory_context) {

  if (TssPKMPrivateKeyMethodProvider::ssl_rsa_connection_index == -1) {
    TssPKMPrivateKeyMethodProvider::ssl_rsa_connection_index =
        SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
  }

  std::string idkey_file_path;
  std::string idkey_contents;
  std::string idkey_auth_type;
  std::string idkey_auth;
  uint8_t idkey_auth_sha1[SHA_DIGEST_LENGTH];

  std::string srk_auth_type;
  std::string srk_auth;
  uint8_t srk_auth_sha1[SHA_DIGEST_LENGTH];

  for (auto& value_it : config.fields()) {
    auto& value = value_it.second;

    // ENVOY_LOG_MISC(debug, "config field {}: {}", value_it.first, value_it.second);

    if (value_it.first == "idkey_file" && value.kind_case() == ProtobufWkt::Value::kStringValue) {
      idkey_file_path = value.string_value();
    }
    if (value_it.first == "idkey_auth" && value.kind_case() == ProtobufWkt::Value::kStringValue) {
      idkey_auth = value.string_value();
    }

    if (value_it.first == "idkey_auth_type" &&
        value.kind_case() == ProtobufWkt::Value::kStringValue) {
      idkey_auth_type = value.string_value();
    }

    if (value_it.first == "srk_auth_type" &&
        value.kind_case() == ProtobufWkt::Value::kStringValue) {
      srk_auth_type = value.string_value();
    }
    if (value_it.first == "srk_auth" && value.kind_case() == ProtobufWkt::Value::kStringValue) {
      srk_auth = value.string_value();
    }
  }

  ASSERT(!idkey_file_path.empty(), "idkey fle is empty");
  idkey_contents = factory_context.api().fileSystem().fileReadToEnd(idkey_file_path);

  if (srk_auth_type == "sha1") {
    hex2binary(srk_auth.c_str(), srk_auth_sha1);
  }

  if (idkey_auth_type == "sha1") {
    hex2binary(idkey_auth.c_str(), idkey_auth_sha1);
  }

  srk = std::make_shared<TpmKey>("", srk_auth_type, srk_auth, srk_auth_sha1);

  idkey = std::make_shared<TpmKey>(idkey_contents, idkey_auth_type, idkey_auth, idkey_auth_sha1);

  method_ = std::make_shared<SSL_PRIVATE_KEY_METHOD>();
  method_->sign = PrivateKeySign;
  method_->decrypt = PrivateKeyDecrypt;
  method_->complete = PrivateKeyComplete;
}

BoringSslPrivateKeyMethodSharedPtr TssPKMPrivateKeyMethodProvider::getBoringSslPrivateKeyMethod() {
  return method_;
}

PrivateKeyMethodProviderSharedPtr
TssPKMPrivateKeyMethodProviderInstanceFactory::createPrivateKeyMethodProviderInstance(
    const envoy::api::v2::auth::PrivateKeyMethod& message,
    Server::Configuration::TransportSocketFactoryContext& private_key_method_provider_context) {

  return PrivateKeyMethodProviderSharedPtr(
      new TssPKMPrivateKeyMethodProvider(message.config(), private_key_method_provider_context));
}

static Registry::RegisterFactory<TssPKMPrivateKeyMethodProviderInstanceFactory,
                                 PrivateKeyMethodProviderInstanceFactory>
    pkm_tss_registered_;

} // namespace Ssl
} // namespace Envoy
