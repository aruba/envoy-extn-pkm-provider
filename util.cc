/*----------------------------------------------------------------------
*
*   Organization: Aruba, a Hewlett Packard Enterprise company
*   Copyright [2019] Hewlett Packard Enterprise Development LP.
* 
*   Licensed under the Apache License, Version 2.0
* 
* ----------------------------------------------------------------------*/


#include <stdio.h>
#include <stdexcept>
#include <iostream>
#include <sstream>
#include <iomanip>

namespace Envoy {
namespace Ssl {

int c2i(char input)
{
  if (input >= '0' && input <= '9')
    return input - '0';
  if (input >= 'A' && input <= 'F')
    return input - 'A' + 10;
  if (input >= 'a' && input <= 'f')
    return input - 'a' + 10;
  throw std::invalid_argument("Input not hexadecimal");
}


void hex2binary(const char* src, uint8_t* target)
{
  while (*src && src[1]) {
    *(target) = c2i(*src) * 16 + c2i(src[1]);
    target ++;
    src += 2;
  }
}

std::string binary2hex(const void *a, size_t len) {
  std::ostringstream ret;
  const unsigned char *in = reinterpret_cast<const unsigned char *>(a);
  for (size_t i = 0; i < len; i++) {
    ret << std::hex << std::setfill('0') << std::setw(2) << std::nouppercase  << (int)in[i];
  }
  return ret.str();
}


void hexdump(const void *a, size_t len) {
  const unsigned char *in = reinterpret_cast<const unsigned char *>(a);
  for (size_t i = 0; i < len; i++) {
    printf("%02x", in[i]);
  }

  printf("\n");
}


} // namespace Ssl
} // namespace Envoy
