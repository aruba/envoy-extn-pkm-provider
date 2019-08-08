/*---------------------------------------------------------------------- 
*
*   Organization: Aruba, a Hewlett Packard Enterprise company
*   Copyright [2019] Hewlett Packard Enterprise Development LP.
* 
*   Licensed under the Apache License, Version 2.0
* 
* ----------------------------------------------------------------------*/



#include "envoy/ssl/private_key/private_key_config.h"
#include "envoy/ssl/private_key/private_key.h"

namespace Envoy {
namespace Ssl {

class PKMPrivateKeyMethodProviderInstanceFactory : public PrivateKeyMethodProviderInstanceFactory {
public:
  PrivateKeyMethodProviderSharedPtr
  createPrivateKeyMethodProviderInstance(const envoy::api::v2::auth::PrivateKeyProvider& message,
                                         Server::Configuration::TransportSocketFactoryContext&
                                             private_key_method_provider_context) override;

  virtual std::string name() const override { return "pkm_provider"; }
};

class PKMPrivateKeyConnection {
public:
  PKMPrivateKeyConnection(bssl::UniquePtr<EVP_PKEY> pkey);
  EVP_PKEY* getPrivateKey() { return pkey_.get(); };

  uint8_t* buf;
  size_t buf_len;

private:
  bssl::UniquePtr<EVP_PKEY> pkey_;
};

class PKMPrivateKeyMethodProvider : public PrivateKeyMethodProvider {
public:
  PKMPrivateKeyMethodProvider(
      const ProtobufWkt::Struct& config,
      Server::Configuration::TransportSocketFactoryContext& factory_context);
  virtual ~PKMPrivateKeyMethodProvider() {}
  virtual BoringSslPrivateKeyMethodSharedPtr getBoringSslPrivateKeyMethod() override;

  virtual void registerPrivateKeyMethod(SSL* ssl, PrivateKeyConnectionCallbacks& cb,
                                        Event::Dispatcher& dispatcher) override;

  virtual void unregisterPrivateKeyMethod(SSL* ssl) override;
  virtual bool checkFips() override;

  static int ssl_rsa_connection_index;

private:
  static std::shared_ptr<SSL_PRIVATE_KEY_METHOD> method_;
  std::string private_key_;
  bssl::UniquePtr<EVP_PKEY> evp_private_key_;
};

} // namespace Ssl
} // namespace Envoy
