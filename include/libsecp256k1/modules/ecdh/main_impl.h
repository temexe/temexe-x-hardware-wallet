/**********************************************************************
 * Copyright (c) 2015 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_MODULE_ECDH_MAIN_
#define _SECP256K1_MODULE_ECDH_MAIN_

#include "include/secp256k1.h"
#include "include/secp256k1_ecdh.h"
#include "ecmult_const_impl.h"



int secp256k1_ecdh_raw(const secp256k1_context* ctx, unsigned char *result, const secp256k1_pubkey *point, const unsigned char *scalar) ;

int secp256k1_ecdh(const secp256k1_context* ctx, unsigned char *result, const secp256k1_pubkey *point, const unsigned char *scalar) ;

#endif
