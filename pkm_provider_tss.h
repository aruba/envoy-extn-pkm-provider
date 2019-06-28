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
#include "tpm/tpm_key.h"

namespace Envoy {
namespace Ssl {

class TssPKMPrivateKeyMethodProviderInstanceFactory
    : public PrivateKeyMethodProviderInstanceFactory {
public:
  PrivateKeyMethodProviderSharedPtr
  createPrivateKeyMethodProviderInstance(const envoy::api::v2::auth::PrivateKeyMethod& message,
                                         Server::Configuration::TransportSocketFactoryContext&
                                             private_key_method_provider_context) override;
  virtual std::string name() const override { return "pkm_provider_tss"; }
};

class TssPKMPrivateKeyConnection : public virtual Ssl::PrivateKeyConnection {
public:
  TssPKMPrivateKeyConnection(SSL* ssl, std::shared_ptr<TpmKey> srk, std::shared_ptr<TpmKey> idkey);

  std::shared_ptr<TpmKey> getSrk() { return srk; };
  std::shared_ptr<TpmKey> getIdKey() { return idkey; };

  uint8_t* buf;
  size_t buf_len;

private:
  std::shared_ptr<TpmKey> srk;
  std::shared_ptr<TpmKey> idkey;
};

class TssPKMPrivateKeyMethodProvider : public PrivateKeyMethodProvider {
public:
  TssPKMPrivateKeyMethodProvider(
      const ProtobufWkt::Struct& config,
      Server::Configuration::TransportSocketFactoryContext& factory_context);
  virtual ~TssPKMPrivateKeyMethodProvider() {}
  virtual PrivateKeyConnectionPtr getPrivateKeyConnection(SSL* ssl,
                                                          PrivateKeyConnectionCallbacks& cb,
                                                          Event::Dispatcher& dispatcher) override;
  virtual BoringSslPrivateKeyMethodSharedPtr getBoringSslPrivateKeyMethod() override;
  static int ssl_rsa_connection_index;

private:
  static std::shared_ptr<SSL_PRIVATE_KEY_METHOD> method_;

  std::shared_ptr<TpmKey> srk;
  std::shared_ptr<TpmKey> idkey;
};

} // namespace Ssl
} // namespace Envoy
