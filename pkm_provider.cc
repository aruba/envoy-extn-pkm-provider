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

#include "pkm_provider.h"

namespace Envoy {
namespace Ssl {

// initialize static members
int PKMPrivateKeyMethodProvider::ssl_rsa_connection_index = -1;
std::shared_ptr<SSL_PRIVATE_KEY_METHOD> PKMPrivateKeyMethodProvider::method_ = NULL;

static ssl_private_key_result_t PrivateKeySign(SSL* ssl, uint8_t* out, size_t* out_len,
                                               size_t max_out, uint16_t signature_algorithm,
                                               const uint8_t* in, size_t in_len) {

  (void)out;
  (void)out_len;
  (void)max_out;

  PKMPrivateKeyConnection* conn = static_cast<PKMPrivateKeyConnection*>(
      SSL_get_ex_data(ssl, PKMPrivateKeyMethodProvider::ssl_rsa_connection_index));

  if (!conn) {
    return ssl_private_key_failure;
  }

  EVP_PKEY* pkey = conn->getPrivateKey();

  const EVP_MD* md = SSL_get_signature_algorithm_digest(signature_algorithm);
  bssl::ScopedEVP_MD_CTX md_context;
  EVP_PKEY_CTX* pkey_context;
  if (!EVP_DigestSignInit(md_context.get(), &pkey_context, md, nullptr, pkey)) {
    return ssl_private_key_failure;
  }

  if (SSL_is_signature_algorithm_rsa_pss(signature_algorithm)) {
    if (!EVP_PKEY_CTX_set_rsa_padding(pkey_context, RSA_PKCS1_PSS_PADDING) ||
        !EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_context, -1 /* salt len = hash len */)) {
      return ssl_private_key_failure;
    }
  }

  size_t len = 0;
  if (!EVP_DigestSign(md_context.get(), nullptr, &len, in, in_len)) {
    return ssl_private_key_failure;
  }

  if (len == 0 || len > max_out) {
    return ssl_private_key_failure;
  }

  conn->buf = static_cast<uint8_t*>(OPENSSL_malloc(len));

  if (!EVP_DigestSign(md_context.get(), conn->buf, &conn->buf_len, in, in_len)) {
    OPENSSL_free(conn->buf);
    return ssl_private_key_failure;
  }

  return ssl_private_key_retry;
}

static ssl_private_key_result_t PrivateKeyDecrypt(SSL* /* ssl */, uint8_t* /* out */,
                                                  size_t* /* out_len */, size_t /* max_out */,
                                                  const uint8_t* /* in */, size_t /* in_len */) {
  // Not implemented
  return ssl_private_key_failure;
}

static ssl_private_key_result_t PrivateKeyComplete(SSL* ssl, uint8_t* out, size_t* out_len,
                                                   size_t max_out) {

  PKMPrivateKeyConnection* conn = static_cast<PKMPrivateKeyConnection*>(
      SSL_get_ex_data(ssl, PKMPrivateKeyMethodProvider::ssl_rsa_connection_index));

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

  SSL_set_ex_data(ssl, PKMPrivateKeyMethodProvider::ssl_rsa_connection_index, nullptr);

  return ssl_private_key_success;
}

PKMPrivateKeyConnection::PKMPrivateKeyConnection(bssl::UniquePtr<EVP_PKEY> pkey)
    : pkey_(move(pkey)) {}

void PKMPrivateKeyMethodProvider::registerPrivateKeyMethod(SSL* ssl,
                                                           Ssl::PrivateKeyConnectionCallbacks& cb,
                                                           Event::Dispatcher& dispatcher) {

  UNREFERENCED_PARAMETER(dispatcher);
  UNREFERENCED_PARAMETER(cb);

  PKMPrivateKeyConnection* ops = new PKMPrivateKeyConnection(bssl::UpRef(evp_private_key_));
  SSL_set_ex_data(ssl, PKMPrivateKeyMethodProvider::ssl_rsa_connection_index, ops);
}

void PKMPrivateKeyMethodProvider::unregisterPrivateKeyMethod(SSL* ssl) {
  PKMPrivateKeyConnection* ops = static_cast<PKMPrivateKeyConnection*>(
      SSL_get_ex_data(ssl, PKMPrivateKeyMethodProvider::ssl_rsa_connection_index));
  SSL_set_ex_data(ssl, PKMPrivateKeyMethodProvider::ssl_rsa_connection_index, nullptr);
  delete ops;
}

PKMPrivateKeyMethodProvider::PKMPrivateKeyMethodProvider(
    const ProtobufWkt::Struct& config,
    Server::Configuration::TransportSocketFactoryContext& factory_context) {

  if (PKMPrivateKeyMethodProvider::ssl_rsa_connection_index == -1) {
    PKMPrivateKeyMethodProvider::ssl_rsa_connection_index =
        SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
  }

  std::string private_key_path;
  for (auto& value_it : config.fields()) {
    auto& value = value_it.second;
    if (value_it.first == "private_key_file" &&
        value.kind_case() == ProtobufWkt::Value::kStringValue) {
      private_key_path = value.string_value();
    }
  }

  ASSERT(!private_key_path.empty());

  private_key_ = factory_context.api().fileSystem().fileReadToEnd(private_key_path);

  bssl::UniquePtr<BIO> bio(
      BIO_new_mem_buf(const_cast<char*>(private_key_.data()), private_key_.size()));
  bssl::UniquePtr<EVP_PKEY> pkey(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
  evp_private_key_ = std::move(pkey);

  method_ = std::make_shared<SSL_PRIVATE_KEY_METHOD>();
  method_->sign = PrivateKeySign;
  method_->decrypt = PrivateKeyDecrypt;
  method_->complete = PrivateKeyComplete;
}

BoringSslPrivateKeyMethodSharedPtr PKMPrivateKeyMethodProvider::getBoringSslPrivateKeyMethod() {
  return method_;
}

bool PKMPrivateKeyMethodProvider::checkFips() {
  RSA* rsa_private_key = EVP_PKEY_get0_RSA(evp_private_key_.get());

  if (rsa_private_key == nullptr || !RSA_check_fips(rsa_private_key)) {
    return false;
  }

  return true;
}

PrivateKeyMethodProviderSharedPtr
PKMPrivateKeyMethodProviderInstanceFactory::createPrivateKeyMethodProviderInstance(
    const envoy::api::v2::auth::PrivateKeyProvider& message,
    Server::Configuration::TransportSocketFactoryContext& private_key_method_provider_context) {

  return PrivateKeyMethodProviderSharedPtr(
      new PKMPrivateKeyMethodProvider(message.config(), private_key_method_provider_context));
}

static Registry::RegisterFactory<PKMPrivateKeyMethodProviderInstanceFactory,
                                 PrivateKeyMethodProviderInstanceFactory>
    pkm_registered_;

} // namespace Ssl
} // namespace Envoy
