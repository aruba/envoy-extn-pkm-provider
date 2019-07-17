# envoy-extn-pkm-provider
Envoy extension for private key method provider.

If you have multiple applications (using different SSL libraries) that need to connect to a server and do TLS mutual auth using a client certificate whose private key is in TPM, then you can use envoyproxy using this extension and have all the apps connect via this proxy. 


# Build

## Requirement

* libtspi-dev (apt-get install -y libtspi-dev)

## Build

* ci/do_ci.sh build
* ci/docker_build.sh

# Configure

* See tls_context in the sample config file at config/tpm_proxy.yaml


# Run

* sudo envoy -c config/tpm_proxy.yaml  [-l debug] - or
* TSS_TCSD_HOSTNAME=<host-ip> docker run -v $(pwd)/config/tpm_proxy.yaml:/etc/envoy/envoy.yaml -p 10000:10000 -e TSS_TCSD_HOSTNAME  envoy:latest -c /etc/envoy/envoy.yaml -l debug

# Access

* curl http://localhost:10000/
* the envoyproxy instance listening on port 10000 further connects to the target server
  initiating TLS connection using the certificate specified in the config file and uses TPM
  for private key operations.


