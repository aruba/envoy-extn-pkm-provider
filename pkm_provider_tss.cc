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

  ENVOY_LOG_MISC(debug, "SSL version: {}, cipher: {}, sigalg: {}", SSL_get_version(ssl), SSL_get_cipher(ssl), SSL_get_signature_algorithm_name(signature_algorithm, 1));

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

TssPKMPrivateKeyConnection::TssPKMPrivateKeyConnection(std::shared_ptr<TpmKey> srk,
                                                       std::shared_ptr<TpmKey> idkey)
    : srk(move(srk)), idkey(move(idkey)) {
}

void TssPKMPrivateKeyMethodProvider::registerPrivateKeyMethod(SSL* ssl,
                                                           Ssl::PrivateKeyConnectionCallbacks& cb,
                                                           Event::Dispatcher& dispatcher) {

  UNREFERENCED_PARAMETER(dispatcher);
  UNREFERENCED_PARAMETER(cb);

  // TPM 1.2 supports only PKCS1 padding for RSA, so we will skip algoritms using PSS padding
  static const char *supported_signature_algorithms = "RSA+SHA256:RSA+SHA384:RSA+SHA512:RSA+SHA";
  if (!SSL_set1_sigalgs_list(ssl, supported_signature_algorithms)) {
      throw EnvoyException("Failed to set sigalgs.");
  }

  TssPKMPrivateKeyConnection *ops = new TssPKMPrivateKeyConnection(srk, idkey);
  SSL_set_ex_data(ssl, TssPKMPrivateKeyMethodProvider::ssl_rsa_connection_index, ops);
}

void TssPKMPrivateKeyMethodProvider::unregisterPrivateKeyMethod(SSL* ssl) {
  TssPKMPrivateKeyConnection* ops = static_cast<TssPKMPrivateKeyConnection*>(
      SSL_get_ex_data(ssl, TssPKMPrivateKeyMethodProvider::ssl_rsa_connection_index));
  SSL_set_ex_data(ssl, TssPKMPrivateKeyMethodProvider::ssl_rsa_connection_index, nullptr);
  delete ops;
}


TssPKMPrivateKeyMethodProvider::TssPKMPrivateKeyMethodProvider(
    const ProtobufWkt::Struct& config,
    Server::Configuration::TransportSocketFactoryContext& factory_context) {

  ENVOY_LOG_MISC(debug, "TssPKMPrivateKeyMethodProvider::TssPKMPrivateKeyMethodProvider");

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
    const envoy::api::v2::auth::PrivateKeyProvider& message,
    Server::Configuration::TransportSocketFactoryContext& private_key_method_provider_context) {

  return PrivateKeyMethodProviderSharedPtr(
      new TssPKMPrivateKeyMethodProvider(message.config(), private_key_method_provider_context));
}


bool TssPKMPrivateKeyMethodProvider::checkFips() {
  return false;
}



static Registry::RegisterFactory<TssPKMPrivateKeyMethodProviderInstanceFactory,
                                 PrivateKeyMethodProviderInstanceFactory>
    pkm_tss_registered_;
/*
REGISTER_FACTORY(TssPKMPrivateKeyMethodProviderInstanceFactory, PrivateKeyMethodProviderInstanceFactory);
*/


} // namespace Ssl
} // namespace Envoy
