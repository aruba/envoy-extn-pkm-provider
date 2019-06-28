/*----------------------------------------------------------------------
*
*   Organization: Aruba, a Hewlett Packard Enterprise company
*   Copyright [2019] Hewlett Packard Enterprise Development LP.
* 
*   Licensed under the Apache License, Version 2.0
* 
* ----------------------------------------------------------------------*/


#include "tpm/tpm_key.h"

namespace Envoy {
namespace Ssl {

class TPMPrivKeyOperator {
public:
  virtual ~TPMPrivKeyOperator() {}
  virtual TPMPrivKeyOperator* loadKey(std::shared_ptr<TpmKey> idkey) = 0;
  virtual RSA* getRSA() = 0;
  virtual int encrypt(const uint8_t* in, size_t in_len, uint8_t* out, size_t* out_len) = 0;
  virtual int decrypt(const uint8_t* in, size_t in_len, uint8_t* out, size_t* out_len) = 0;
};

class TPMPrivKeyOperatorImpl : TPMPrivKeyOperator {
public:
  TPMPrivKeyOperatorImpl(std::shared_ptr<TpmKey> srk);
  virtual ~TPMPrivKeyOperatorImpl();
  virtual TPMPrivKeyOperator* loadKey(std::shared_ptr<TpmKey> idkey);
  virtual RSA* getRSA();
  virtual int encrypt(const uint8_t* in, size_t in_len, uint8_t* out, size_t* out_len);
  virtual int decrypt(const uint8_t* in, size_t in_len, uint8_t* out, size_t* out_len);

private:
  TSS_HCONTEXT hContext;
  TSS_HKEY hSRK;
  TSS_HKEY hKey;
  RSA* rsa;

  void loadSrk(std::shared_ptr<TpmKey> srk);
  void unloadKey();
  RSA* constructRSAObject();
};

} // namespace Ssl
} // namespace Envoy
