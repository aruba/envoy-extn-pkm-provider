
#include "envoy/ssl/private_key/private_key_config.h"
#include "envoy/ssl/private_key/private_key.h"



namespace Envoy {
namespace Ssl {

class PKMPrivateKeyMethodProviderInstanceFactory : public PrivateKeyMethodProviderInstanceFactory {
public:
  PrivateKeyMethodProviderSharedPtr
  createPrivateKeyMethodProviderInstance(const envoy::api::v2::auth::PrivateKeyMethod& message,
                                         Server::Configuration::TransportSocketFactoryContext&
                                             private_key_method_provider_context) override ;
    virtual std::string name() const  {
      return "pkm_provider";
    }
};


class PKMPrivateKeyConnection : public virtual Ssl::PrivateKeyConnection {
public:
  PKMPrivateKeyConnection(SSL* ssl,bssl::UniquePtr<EVP_PKEY> pkey);
  EVP_PKEY* getPrivateKey() { return pkey_.get(); };

private: 
  bssl::UniquePtr<EVP_PKEY> pkey_;
 
};


class PKMPrivateKeyMethodProvider : public PrivateKeyMethodProvider {
public:
  PKMPrivateKeyMethodProvider(const ProtobufWkt::Struct& config,
    Server::Configuration::TransportSocketFactoryContext& factory_context);
  virtual ~PKMPrivateKeyMethodProvider() {}
  virtual PrivateKeyConnectionPtr getPrivateKeyConnection(SSL* ssl,
                                                          PrivateKeyConnectionCallbacks& cb,
                                                          Event::Dispatcher& dispatcher)  override;
  virtual BoringSslPrivateKeyMethodSharedPtr getBoringSslPrivateKeyMethod() override;
  static int ssl_rsa_connection_index;

private:
  static std::shared_ptr<SSL_PRIVATE_KEY_METHOD> method_;
  std::string private_key_;
};



} // namespace Ssl
} // namespace Envoy
