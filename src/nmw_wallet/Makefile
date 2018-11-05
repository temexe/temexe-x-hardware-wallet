CXX = g++
BOOST_BASE = ../../../../boost_1_65_1
BOOST_LIBS = $(BOOST_BASE)/stage/lib/libboost*.a
CFLAGS =  -I../../include -I../../include/libsecp256k1/include -I../../include/libsecp256k1 -I$(BOOST_BASE) -DWITH_ICU -DBOOST_LOG_DYN_LINK 
INC = ../../include
INCBC = $(INC)/bitcoin/bitcoin
INCBCLIENT = $(INC)/bitcoin/client
INCBCPROC = $(INC)/bitcoin/protocol
OBJS_TEST = test_example.o
OBJS_ETHE = main_ethereum.o
OBJS_MAIN = main_example.o
DIRE = $(INC)/libdevcrypto
DIRC = $(INC)/libdevcore
DIREA = $(INC)/libethash
DIREC = $(INC)/libethcore
DIRB = $(INCBC)/wallet
DIRBU = $(INCBC)/utility
DIRCR = $(INC)/cryptopp
DIRM = $(INCBC)/math
DIRL = /usr/lib/x86_64-linux-gnu
DIRUNI = $(INCBC)/unicode
DIRSEC = $(INC)/libsecp256k1
DIRJSON= $(INC)/json
OBJS = nmw_wallet_core.o  \
    $(DIRBU)/pseudo_random.o $(DIRBU)/string.o $(DIRBU)/istream_reader.o  $(DIRBU)/ostream_writer.o	$(DIRBU)/binary.o\
	$(INCBC)/error.o \
	$(DIRUNI)/unicode.o $(DIRUNI)/console_streambuf.o $(DIRUNI)/unicode_istream.o $(DIRUNI)/unicode_ostream.o \
	$(DIRM)/hash.o $(DIRM)/elliptic_curve.o \
	$(INCBC)/chain/script.o $(INCBC)/chain/transaction.o  $(INCBC)/chain/input.o  $(INCBC)/chain/point.o  $(INCBC)/chain/output.o $(INCBC)/chain/witness.o $(INCBC)/chain/chain_state.o $(INCBC)/chain/output_point.o $(INCBC)/chain/header.o  $(INCBC)/chain/block.o  $(INCBC)/chain/compact.o $(INCBC)/chain/point_iterator.o $(INCBC)/chain/points_value.o $(INCBC)/chain/point_value.o \
	$(INCBC)/message/messages.o $(INCBC)/message/network_address.o \
	$(INCBC)/config/checkpoint.o $(INCBC)/config/endpoint.o $(INCBC)/config/authority.o $(INCBC)/config/sodium.o\
	$(INCBC)/machine/number.o $(INCBC)/machine/operation.o  $(INCBC)/machine/program.o   $(INCBC)/machine/opcode.o  $(INCBC)/machine/interpreter.o \
	$(INC)/secp256k1_initializer.o \
	$(DIRM)/checksum.o \
	$(DIRB)/ec_private.o $(DIRB)/ec_public.o $(DIRB)/hd_private.o $(DIRB)/hd_public.o \
	$(INCBC)/formats/base_16.o $(INCBC)/formats/base_58.o $(INCBC)/formats/base_10.o $(INCBC)/formats/base_85.o \
	$(DIRC)/SHA3.o $(DIRC)/RLP.o $(DIRC)/CommonData.o $(DIRC)/FixedHash.o  $(DIRC)/Address.o   $(DIRC)/CommonIO.o   $(DIRC)/FileSystem.o $(DIRC)/MemoryDB.o $(DIRC)/TrieCommon.o $(DIRC)/TrieHash.o  $(DIRC)/CommonJS.o \
	$(DIRE)/Common.o $(DIRE)/CryptoPP.o  $(DIRE)/AES.o  $(DIRE)/Hash.o $(DIRE)/SecretStore.o \
	$(DIRCR)/algparam.o $(DIRCR)/arc4.o $(DIRCR)/asn.o $(DIRCR)/authenc.o $(DIRCR)/basecode.o  $(DIRCR)/cpu.o $(DIRCR)/crc.o $(DIRCR)/cryptlib.o  $(DIRCR)/des.o $(DIRCR)/dessp.o  $(DIRCR)/dll.o $(DIRCR)/dsa.o $(DIRCR)/ec2n.o $(DIRCR)/ecp.o $(DIRCR)/emsa2.o  $(DIRCR)/files.o $(DIRCR)/filters.o $(DIRCR)/fips140.o  $(DIRCR)/gf2_32.o $(DIRCR)/gf256.o $(DIRCR)/gf2n.o $(DIRCR)/gfpcrypt.o  $(DIRCR)/hex.o $(DIRCR)/hmac.o $(DIRCR)/hrtimer.o $(DIRCR)/integer.o $(DIRCR)/iterhash.o $(DIRCR)/keccak.o  $(DIRCR)/md5.o $(DIRCR)/misc.o \
	$(DIRCR)/modes.o $(DIRCR)/mqueue.o  $(DIRCR)/nbtheory.o  $(DIRCR)/oaep.o $(DIRCR)/osrng.o  $(DIRCR)/pkcspad.o $(DIRCR)/pssr.o $(DIRCR)/pubkey.o $(DIRCR)/queue.o $(DIRCR)/randpool.o $(DIRCR)/rdrand.o $(DIRCR)/rdtables.o $(DIRCR)/rijndael.o $(DIRCR)/ripemd.o $(DIRCR)/rng.o $(DIRCR)/rsa.o  $(DIRCR)/seed.o $(DIRCR)/sha3.o $(DIRCR)/shacal2.o $(DIRCR)/sha.o   \
	$(DIRB)/dictionary.o $(DIRB)/mnemonic.o  $(DIRB)/payment_address.o $(DIRB)/stealth_address.o $(DIRB)/select_outputs.o\
	$(DIREC)/TransactionBase.o $(DIREC)/Common.o $(DIREC)/BlockHeader.o \
	$(DIRJSON)/json_reader.o $(DIRJSON)/json_value.o  $(DIRJSON)/json_writer.o 

DIRME = $(INCBC)/math/external
OBJSC = $(DIRME)/pkcs5_pbkdf2.o $(DIRME)/hmac_sha512.o $(DIRME)/sha512.o $(DIRME)/zeroize.o \
	$(DIRME)/crypto_scrypt.o $(DIRME)/hmac_sha256.o  $(DIRME)/sha256.o $(DIRME)/ripemd160.o \
	$(DIRME)/sha1.o $(DIRME)/pbkdf2_sha256.o $(DIRME)/lax_der_parsing.o \
	$(INC)/crypto_scrypt-nosse.o $(INC)/sha256.o \
	$(INC)/ethash/keccak.o $(INC)/ethash/keccakf1600.o 

OBJSCSECP = $(DIRSEC)/hash_impl.o $(DIRSEC)/modules/ecdh/main_impl.o $(DIRSEC)/secp256k1.o 

TARGET = test_example 
RM = rm -f

$(TARGET):$(OBJS) $(OBJS_TEST) $(OBJSC) $(OBJSCSECP)  #$(OBJS_MAIN)
	ar cr libwalletcore.a $(OBJS) $(OBJSC) $(OBJSCSECP) 
	g++ -O2 -std=c++11 $(OBJS_TEST) -o test_example $(CFLAGS) -L/usr/lib/x86_64-linux-gnu ./libwalletcore.a $(BOOST_LIBS) -lpthread 


$(OBJS):%.o:%.cpp
	g++ -O2 -std=c++11  -c $(CFLAGS) $< -o $@

$(OBJSC):%.o:%.c
	g++ -O2 -std=c++11 -c $(CFLAGS) $< -o $@

$(OBJSCSECP):%.o:%.c
	g++ -O2 -std=c++11 -c $(CFLAGS) $< -o $@

$(OBJS_TEST):%.o:%.cpp
	g++ -O2 -std=c++11 -c $(CFLAGS) $< -o $@

$(OBJS_MAIN):%.o:%.cpp
	g++ -O2 -std=c++11 -c $(CFLAGS) $< -o $@

# $(OBJS_ETHE):%.o:%.cpp
	# g++ -O2 -std=c++11 -c $(CFLAGS) $< -o $@


clean:
	$(RM) $(TARGET) $(OBJS)
