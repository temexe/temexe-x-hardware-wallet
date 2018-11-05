project(wallet_core)
CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
add_compile_options(-DWITH_ICU -DBOOST_LOG_DYN_LINK)
include_directories(../include /Users/laborc/code/gitos/nmw/wallet/Boost-for-Android/boost_1_65_1 ../include/libsecp256k1 ../include/libsecp256k1/include)

set(SOURCE_PATH ../src/nmw_wallet)
set(INC ../include)
set(INCBC ${INC}/bitcoin/bitcoin)
set(INCBCLIENT ${INC}/bitcoin/client)
set(INCBCPROC ${INC}/bitcoin/protocol)
set(DIRE ${INC}/libdevcrypto)
set(DIRC ${INC}/libdevcore)
set(DIREA ${INC}/libethash)
set(DIREC ${INC}/libethcore)
set(DIRB ${INCBC}/wallet)
set(DIRBU ${INCBC}/utility)
set(DIRCR ${INC}/cryptopp)
set(DIRM ${INCBC}/math)
set(DIRUNI ${INCBC}/unicode)
set(DIRSEC ${INC}/libsecp256k1)
set(DIRME ${INCBC}/math/external)

set(SOURCE_FILES 
	${SOURCE_PATH}/nmw_wallet_core.cpp

    ${DIRBU}/pseudo_random.cpp ${DIRBU}/string.cpp ${DIRBU}/istream_reader.cpp  ${DIRBU}/ostream_writer.cpp	${DIRBU}/binary.cpp
	${INCBC}/error.cpp 
	${DIRUNI}/unicode.cpp ${DIRUNI}/console_streambuf.cpp ${DIRUNI}/unicode_istream.cpp ${DIRUNI}/unicode_ostream.cpp 
	${DIRM}/hash.cpp ${DIRM}/elliptic_curve.cpp 
	${INCBC}/chain/script.cpp ${INCBC}/chain/transaction.cpp  ${INCBC}/chain/input.cpp  ${INCBC}/chain/point.cpp  ${INCBC}/chain/output.cpp ${INCBC}/chain/witness.cpp ${INCBC}/chain/chain_state.cpp ${INCBC}/chain/output_point.cpp ${INCBC}/chain/header.cpp  ${INCBC}/chain/block.cpp  ${INCBC}/chain/compact.cpp ${INCBC}/chain/point_iterator.cpp ${INCBC}/chain/points_value.cpp ${INCBC}/chain/point_value.cpp 
	${INCBC}/message/messages.cpp ${INCBC}/message/network_address.cpp 
	${INCBC}/config/checkpoint.cpp ${INCBC}/config/endpoint.cpp ${INCBC}/config/authority.cpp ${INCBC}/config/sodium.cpp
	${INCBC}/machine/number.cpp ${INCBC}/machine/operation.cpp  ${INCBC}/machine/program.cpp   ${INCBC}/machine/opcode.cpp  ${INCBC}/machine/interpreter.cpp 
	${INC}/secp256k1_initializer.cpp 
	${DIRM}/checksum.cpp 
	${DIRB}/ec_private.cpp ${DIRB}/ec_public.cpp ${DIRB}/hd_private.cpp ${DIRB}/hd_public.cpp 
	${INCBC}/formats/base_16.cpp ${INCBC}/formats/base_58.cpp ${INCBC}/formats/base_10.cpp ${INCBC}/formats/base_85.cpp 
	${DIRC}/SHA3.cpp ${DIRC}/RLP.cpp ${DIRC}/CommonData.cpp ${DIRC}/FixedHash.cpp  ${DIRC}/Address.cpp   ${DIRC}/CommonIO.cpp   ${DIRC}/FileSystem.cpp ${DIRC}/MemoryDB.cpp ${DIRC}/TrieCommon.cpp ${DIRC}/TrieHash.cpp  
	${DIRE}/Common.cpp ${DIRE}/CryptoPP.cpp  ${DIRE}/AES.cpp  ${DIRE}/Hash.cpp ${DIRE}/SecretStore.cpp 
	${DIRCR}/algparam.cpp ${DIRCR}/arc4.cpp ${DIRCR}/asn.cpp ${DIRCR}/authenc.cpp ${DIRCR}/basecode.cpp  ${DIRCR}/cpu.cpp ${DIRCR}/crc.cpp ${DIRCR}/cryptlib.cpp  ${DIRCR}/des.cpp ${DIRCR}/dessp.cpp  ${DIRCR}/dll.cpp ${DIRCR}/dsa.cpp ${DIRCR}/ec2n.cpp ${DIRCR}/eccrypto.cpp ${DIRCR}/ecp.cpp ${DIRCR}/elgamal.cpp ${DIRCR}/emsa2.cpp ${DIRCR}/eprecomp.cpp ${DIRCR}/files.cpp ${DIRCR}/filters.cpp ${DIRCR}/fips140.cpp  ${DIRCR}/gf2_32.cpp ${DIRCR}/gf256.cpp ${DIRCR}/gf2n.cpp ${DIRCR}/gfpcrypt.cpp  ${DIRCR}/hex.cpp ${DIRCR}/hmac.cpp ${DIRCR}/hrtimer.cpp ${DIRCR}/integer.cpp ${DIRCR}/iterhash.cpp ${DIRCR}/keccak.cpp  ${DIRCR}/md5.cpp ${DIRCR}/misc.cpp 
	 ${DIRCR}/modes.cpp ${DIRCR}/mqueue.cpp  ${DIRCR}/nbtheory.cpp  ${DIRCR}/oaep.cpp ${DIRCR}/osrng.cpp  ${DIRCR}/pkcspad.cpp ${DIRCR}/pssr.cpp ${DIRCR}/pubkey.cpp ${DIRCR}/queue.cpp ${DIRCR}/randpool.cpp ${DIRCR}/rdrand.cpp ${DIRCR}/rdtables.cpp ${DIRCR}/rijndael.cpp ${DIRCR}/ripemd.cpp ${DIRCR}/rng.cpp ${DIRCR}/rsa.cpp  ${DIRCR}/seed.cpp ${DIRCR}/sha3.cpp ${DIRCR}/shacal2.cpp ${DIRCR}/sha.cpp   
	${DIRB}/dictionary.cpp ${DIRB}/mnemonic.cpp  ${DIRB}/payment_address.cpp ${DIRB}/stealth_address.cpp ${DIRB}/select_outputs.cpp
	${DIREC}/TransactionBase.cpp ${DIREC}/Common.cpp ${DIREC}/BlockHeader.cpp 
	${INCBCPROC}/settings.cpp

    ${DIRME}/pkcs5_pbkdf2.c ${DIRME}/hmac_sha512.c ${DIRME}/sha512.c ${DIRME}/zeroize.c 
	${DIRME}/crypto_scrypt.c ${DIRME}/hmac_sha256.c  ${DIRME}/sha256.c ${DIRME}/ripemd160.c 
	${DIRME}/sha1.c ${DIRME}/pbkdf2_sha256.c ${DIRME}/lax_der_parsing.c 
	${INC}/crypto_scrypt-nosse.c ${INC}/sha256.c 
	${INC}/ethash/keccak.c ${INC}/ethash/keccakf1600.c


    ${DIRSEC}/hash_impl.c ${DIRSEC}/modules/ecdh/main_impl.c ${DIRSEC}/gen_context.c ${DIRSEC}/secp256k1.c 
)

add_library(walletcore STATIC ${SOURCE_FILES})
target_link_libraries(walletcore /Users/laborc/Documents/tmp/wallet-test-ios/wallet-test/libs/libboost.a)
