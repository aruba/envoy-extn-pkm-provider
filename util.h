/*----------------------------------------------------------------------
*
*   Organization: Aruba, a Hewlett Packard Enterprise company
*   Copyright [2019] Hewlett Packard Enterprise Development LP.
* 
*   Licensed under the Apache License, Version 2.0
* 
* ----------------------------------------------------------------------*/


#include <string>

namespace Envoy {
namespace Ssl {

void hex2binary(const char* src, uint8_t* target);
std::string binary2hex(const void *a, size_t len);
void hexdump(const void *a, size_t len);

 
} // namespace Ssl
} // namespace Envoy
