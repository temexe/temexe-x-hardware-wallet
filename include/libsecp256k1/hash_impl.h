/**********************************************************************
 * Copyright (c) 2014 Pieter Wuille                                   *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_HASH_IMPL_H
#define SECP256K1_HASH_IMPL_H

#include "secp256k1_sha256.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

 void secp256k1_sha256_initialize(secp256k1_sha256_t *hash);
/** Perform one SHA-256 transformation, processing 16 big endian 32-bit words. */
 void secp256k1_sha256_transform(uint32_t* s, const uint32_t* chunk);

 void secp256k1_sha256_write(secp256k1_sha256_t *hash, const unsigned char *data, size_t len);

 void secp256k1_sha256_finalize(secp256k1_sha256_t *hash, unsigned char *out32) ;

 void secp256k1_hmac_sha256_initialize(secp256k1_hmac_sha256_t *hash, const unsigned char *key, size_t keylen);

 void secp256k1_hmac_sha256_write(secp256k1_hmac_sha256_t *hash, const unsigned char *data, size_t size) ;

 void secp256k1_hmac_sha256_finalize(secp256k1_hmac_sha256_t *hash, unsigned char *out32) ;

 void secp256k1_rfc6979_hmac_sha256_initialize(secp256k1_rfc6979_hmac_sha256_t *rng, const unsigned char *key, size_t keylen);

 void secp256k1_rfc6979_hmac_sha256_generate(secp256k1_rfc6979_hmac_sha256_t *rng, unsigned char *out, size_t outlen);

 void secp256k1_rfc6979_hmac_sha256_finalize(secp256k1_rfc6979_hmac_sha256_t *rng);



#endif /* SECP256K1_HASH_IMPL_H */
