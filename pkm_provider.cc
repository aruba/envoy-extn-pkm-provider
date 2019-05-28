#include "envoy/ssl/private_key/private_key_config.h"
#include "envoy/server/transport_socket_config.h"

#include "pkm_provider.h"

namespace Envoy {
namespace Ssl {

// initialize static members
int PKMPrivateKeyMethodProvider::ssl_rsa_connection_index = -1;
std::shared_ptr<SSL_PRIVATE_KEY_METHOD> PKMPrivateKeyMethodProvider::method_ = NULL;

static ssl_private_key_result_t PrivateKeySign(
    SSL *ssl, uint8_t *out, size_t *out_len, size_t max_out,
    uint16_t signature_algorithm, const uint8_t *in, size_t in_len) {
  
  size_t len = 0;
  
  PKMPrivateKeyConnection* conn = static_cast<PKMPrivateKeyConnection*>(
      SSL_get_ex_data(ssl, PKMPrivateKeyMethodProvider::ssl_rsa_connection_index));
  EVP_PKEY* pkey = conn->getPrivateKey();


  const EVP_MD *md = SSL_get_signature_algorithm_digest(signature_algorithm);
  bssl::ScopedEVP_MD_CTX md_context;
  EVP_PKEY_CTX *pkey_context;
  if (!EVP_DigestSignInit(md_context.get(), &pkey_context, md, nullptr,
                          pkey)) {
    return ssl_private_key_failure;
  }

  
  if (SSL_is_signature_algorithm_rsa_pss(signature_algorithm)) {
    if (!EVP_PKEY_CTX_set_rsa_padding(pkey_context, RSA_PKCS1_PSS_PADDING) ||
        !EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_context, -1 /* salt len = hash len */)) {
      return ssl_private_key_failure;
    }
  }

  if (!EVP_DigestSign(md_context.get(), nullptr, &len, in, in_len)) {
    return ssl_private_key_failure;
  }

  if (len == 0 || len > max_out) {
    return ssl_private_key_failure;
  }

  uint8_t *buf = static_cast<uint8_t*>(OPENSSL_malloc(len));

  if (!EVP_DigestSign(md_context.get(), buf, &len, in, in_len)) {
    OPENSSL_free(buf);
    return ssl_private_key_failure;
  }

  memcpy(out, buf, len);
  *out_len = len;
  OPENSSL_free(buf);

  return ssl_private_key_success;
}

static ssl_private_key_result_t PrivateKeyDecrypt(SSL *    /* ssl */, 
                                                 uint8_t * /* out */,
                                                 size_t *  /* out_len */,
                                                 size_t    /* max_out */,
                                                 const uint8_t * /* in */,
                                                 size_t    /* in_len */) {
  // Not implemented
  return ssl_private_key_failure;
}

static ssl_private_key_result_t PrivateKeyComplete(SSL *    /* ssl */, 
                                                  uint8_t * /* out */,
                                                  size_t  * /* out_len */,
                                                  size_t    /* max_out */) {

  return ssl_private_key_success;
}


PKMPrivateKeyConnection::PKMPrivateKeyConnection(SSL* ssl, 
                                                 bssl::UniquePtr<EVP_PKEY> pkey)
    : pkey_(move(pkey)) {
  SSL_set_ex_data(ssl, PKMPrivateKeyMethodProvider::ssl_rsa_connection_index, this);
}

Ssl::PrivateKeyConnectionPtr PKMPrivateKeyMethodProvider::getPrivateKeyConnection(
    SSL* ssl, Ssl::PrivateKeyConnectionCallbacks& cb, Event::Dispatcher& dispatcher) {

  (void) cb;
  (void) dispatcher;

  bssl::UniquePtr<BIO> bio(
      BIO_new_mem_buf(const_cast<char*>(private_key_.data()), private_key_.size()));
  bssl::UniquePtr<EVP_PKEY> pkey(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
  if (pkey == nullptr) {
    return nullptr;
  }

  return std::make_unique<PKMPrivateKeyConnection>(ssl, move(pkey));
}



PKMPrivateKeyMethodProvider::PKMPrivateKeyMethodProvider(const ProtobufWkt::Struct& config,
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
  
  method_ = std::make_shared<SSL_PRIVATE_KEY_METHOD>();
  method_->sign     = PrivateKeySign;
  method_->decrypt  = PrivateKeyDecrypt;
  method_->complete = PrivateKeyComplete;

}


BoringSslPrivateKeyMethodSharedPtr PKMPrivateKeyMethodProvider::getBoringSslPrivateKeyMethod() {
 return method_;
}


PrivateKeyMethodProviderSharedPtr
PKMPrivateKeyMethodProviderInstanceFactory::createPrivateKeyMethodProviderInstance(const envoy::api::v2::auth::PrivateKeyMethod& message,
                                       Server::Configuration::TransportSocketFactoryContext&
                                           private_key_method_provider_context)  {

  return PrivateKeyMethodProviderSharedPtr(new PKMPrivateKeyMethodProvider(message.config(), private_key_method_provider_context));

}


static Registry::RegisterFactory<PKMPrivateKeyMethodProviderInstanceFactory, PrivateKeyMethodProviderInstanceFactory> pkm_registered_;

} // namespace Ssl
} // namespace Envoy

