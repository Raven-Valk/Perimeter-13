#pragma once
#include <openssl/hmac.h>
#include <openssl/evp.h>
typedef int mbedtls_md_type_t; typedef void mbedtls_md_info_t;
#define MBEDTLS_MD_SHA256 6
inline const mbedtls_md_info_t* mbedtls_md_info_from_type(int){ return (const mbedtls_md_info_t*)1; }
inline int mbedtls_md_hmac(const mbedtls_md_info_t*, const unsigned char* key, size_t kl, const unsigned char* in, size_t il, unsigned char* out){
  unsigned int ol=32; HMAC(EVP_sha256(), key, (int)kl, in, il, out, &ol); return 0; }
