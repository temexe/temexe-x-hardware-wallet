LOCAL_PATH := $(call my-dir)  

INC := ../../include
INCBC := $(INC)/bitcoin/bitcoin
INCBCLIENT = $(INC)/bitcoin/client
INCBCPROC = $(INC)/bitcoin/protocol
INCZMQ = $(INC)/libzmq
DIRE := $(INC)/libdevcrypto
DIRC := $(INC)/libdevcore
DIREA := $(INC)/libethash
DIREC = $(INC)/libethcore
DIRB := $(INCBC)/wallet
DIRBU := $(INCBC)/utility
DIRCR := $(INC)/cryptopp
DIRM := $(INCBC)/math
DIRUNI := $(INCBC)/unicode
DIRME := $(INCBC)/math/external
DIRSEC := $(INC)/libsecp256k1
BOOSTLIB := /Users/laborc/Documents/tmp/wallet-test-android/app/src/main/libs/armeabi-v7a

include $(CLEAR_VARS)
LOCAL_MODULE := boost_log_setup
LOCAL_SRC_FILES := $(BOOSTLIB)/libboost_log_setup.a
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := boost_log
LOCAL_SRC_FILES := $(BOOSTLIB)/libboost_log.a
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := boost_chrono
LOCAL_SRC_FILES := $(BOOSTLIB)/libboost_chrono.a
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := boost_date_time
LOCAL_SRC_FILES := $(BOOSTLIB)/libboost_date_time.a
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := boost_filesystem
LOCAL_SRC_FILES := $(BOOSTLIB)/libboost_filesystem.a
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := boost_iostreams
LOCAL_SRC_FILES := $(BOOSTLIB)/libboost_iostreams.a
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := boost_program_options
LOCAL_SRC_FILES := $(BOOSTLIB)/libboost_program_options.a
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := boost_system
LOCAL_SRC_FILES := $(BOOSTLIB)/libboost_system.a
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := boost_regex
LOCAL_SRC_FILES := $(BOOSTLIB)/libboost_regex.a
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := boost_thread
LOCAL_SRC_FILES := $(BOOSTLIB)/libboost_thread.a
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)  
LOCAL_MODULE := walletcore  
LOCAL_ARM_NEON := true

LOCAL_C_INCLUDES := /Users/laborc/code/gitos/nmw/wallet/Boost-for-Android/build/out/armeabi-v7a/include/boost-1_65_1
LOCAL_C_INCLUDES += $(LOCAL_PATH)/../../include
LOCAL_C_INCLUDES += $(LOCAL_PATH)/../../include/libsecp256k1/include
LOCAL_C_INCLUDES += $(LOCAL_PATH)/../../include/libsecp256k1

LOCAL_STATIC_LIBRARIES := boost_log_setup 
LOCAL_STATIC_LIBRARIES += boost_log 
LOCAL_STATIC_LIBRARIES += boost_chrono
LOCAL_STATIC_LIBRARIES += boost_date_time
LOCAL_STATIC_LIBRARIES += boost_filesystem
LOCAL_STATIC_LIBRARIES += boost_iostreams
LOCAL_STATIC_LIBRARIES += boost_program_options
LOCAL_STATIC_LIBRARIES += boost_system
LOCAL_STATIC_LIBRARIES += boost_regex
LOCAL_STATIC_LIBRARIES += boost_thread

# $(DIRCR)/tea.cpp after $(DIRCR)/test.cpp
# $(DIRCR)/basecode.cpp after $(DIRCR)/bench1.cpp $(DIRCR)/bench2.cpp
# $(DIRCR)/cryptlib.cpp after $(DIRCR)/datatest.cpp 
# $(DIRCR)/twofish.cpp after $(DIRCR)/validat1.cpp $(DIRCR)/validat2.cpp $(DIRCR)/validat3.cpp
# $(INCBC)/chain/header.cpp after $(INCBC)/chain/block.cpp
# $(DIRCR)/dll.cpp after $(DIRCR)/dlltest.cpp
# $(DIRCR)/fipsalgt.cpp after $(DIRCR)/fipstest.cpp
# $(INCBC)/machine/number.cpp $(INCBC)/machine/operation.cpp  $(INCBC)/machine/program.cpp   $(INCBC)/machine/opcode.cpp  $(INCBC)/machine/interpreter.cpp \


FILE_LIST := $(DIRBU)/pseudo_random.cpp $(DIRBU)/string.cpp $(DIRBU)/istream_reader.cpp  $(DIRBU)/ostream_writer.cpp	$(DIRBU)/binary.cpp\
	$(INCBC)/error.cpp \
	$(DIRUNI)/unicode.cpp $(DIRUNI)/console_streambuf.cpp $(DIRUNI)/unicode_istream.cpp $(DIRUNI)/unicode_ostream.cpp \
	$(DIRM)/hash.cpp $(DIRM)/elliptic_curve.cpp \
	$(INCBC)/chain/script.cpp $(INCBC)/chain/transaction.cpp  $(INCBC)/chain/input.cpp  $(INCBC)/chain/point.cpp  $(INCBC)/chain/output.cpp $(INCBC)/chain/witness.cpp $(INCBC)/chain/chain_state.cpp $(INCBC)/chain/output_point.cpp $(INCBC)/chain/header.cpp  $(INCBC)/chain/block.cpp  $(INCBC)/chain/compact.cpp $(INCBC)/chain/point_iterator.cpp $(INCBC)/chain/points_value.cpp $(INCBC)/chain/point_value.cpp \
	$(INCBC)/message/messages.cpp $(INCBC)/message/network_address.cpp \
	$(INCBC)/config/checkpoint.cpp $(INCBC)/config/endpoint.cpp $(INCBC)/config/authority.cpp $(INCBC)/config/sodium.cpp\
	$(INCBC)/machine/number.cpp $(INCBC)/machine/operation.cpp  $(INCBC)/machine/program.cpp   $(INCBC)/machine/opcode.cpp  $(INCBC)/machine/interpreter.cpp \
	$(INC)/secp256k1_initializer.cpp \
	$(DIRM)/checksum.cpp \
	$(DIRB)/ec_private.cpp $(DIRB)/ec_public.cpp $(DIRB)/hd_private.cpp $(DIRB)/hd_public.cpp \
	$(INCBC)/formats/base_16.cpp $(INCBC)/formats/base_58.cpp $(INCBC)/formats/base_10.cpp $(INCBC)/formats/base_85.cpp \
	$(DIRC)/SHA3.cpp $(DIRC)/RLP.cpp $(DIRC)/CommonData.cpp $(DIRC)/FixedHash.cpp  $(DIRC)/Address.cpp   $(DIRC)/CommonIO.cpp   $(DIRC)/FileSystem.cpp $(DIRC)/MemoryDB.cpp $(DIRC)/TrieCommon.cpp $(DIRC)/TrieHash.cpp  \
	$(DIRE)/Common.cpp $(DIRE)/CryptoPP.cpp  $(DIRE)/AES.cpp  $(DIRE)/Hash.cpp $(DIRE)/SecretStore.cpp \
	$(DIRCR)/algparam.cpp $(DIRCR)/arc4.cpp $(DIRCR)/asn.cpp $(DIRCR)/authenc.cpp $(DIRCR)/basecode.cpp  $(DIRCR)/cpu.cpp $(DIRCR)/crc.cpp $(DIRCR)/cryptlib.cpp  $(DIRCR)/des.cpp $(DIRCR)/dessp.cpp  $(DIRCR)/dll.cpp $(DIRCR)/dsa.cpp $(DIRCR)/ec2n.cpp $(DIRCR)/eccrypto.cpp $(DIRCR)/ecp.cpp $(DIRCR)/elgamal.cpp $(DIRCR)/emsa2.cpp $(DIRCR)/eprecomp.cpp $(DIRCR)/files.cpp $(DIRCR)/filters.cpp $(DIRCR)/fips140.cpp  $(DIRCR)/gf2_32.cpp $(DIRCR)/gf256.cpp $(DIRCR)/gf2n.cpp $(DIRCR)/gfpcrypt.cpp  $(DIRCR)/hex.cpp $(DIRCR)/hmac.cpp $(DIRCR)/hrtimer.cpp $(DIRCR)/integer.cpp $(DIRCR)/iterhash.cpp $(DIRCR)/keccak.cpp  $(DIRCR)/md5.cpp $(DIRCR)/misc.cpp \
	 $(DIRCR)/modes.cpp $(DIRCR)/mqueue.cpp  $(DIRCR)/nbtheory.cpp  $(DIRCR)/oaep.cpp $(DIRCR)/osrng.cpp  $(DIRCR)/pkcspad.cpp $(DIRCR)/pssr.cpp $(DIRCR)/pubkey.cpp $(DIRCR)/queue.cpp $(DIRCR)/randpool.cpp $(DIRCR)/rdrand.cpp $(DIRCR)/rdtables.cpp $(DIRCR)/rijndael.cpp $(DIRCR)/ripemd.cpp $(DIRCR)/rng.cpp $(DIRCR)/rsa.cpp  $(DIRCR)/seed.cpp $(DIRCR)/sha3.cpp $(DIRCR)/shacal2.cpp $(DIRCR)/sha.cpp   \
	$(DIRB)/dictionary.cpp $(DIRB)/mnemonic.cpp  $(DIRB)/payment_address.cpp $(DIRB)/stealth_address.cpp $(DIRB)/select_outputs.cpp\
	$(DIREC)/TransactionBase.cpp $(DIREC)/Common.cpp $(DIREC)/BlockHeader.cpp \
	$(INCBCPROC)/settings.cpp
	

FILE_LIST += $(DIRME)/pkcs5_pbkdf2.c $(DIRME)/hmac_sha512.c $(DIRME)/sha512.c $(DIRME)/zeroize.c \
	$(DIRME)/crypto_scrypt.c $(DIRME)/hmac_sha256.c  $(DIRME)/sha256.c $(DIRME)/ripemd160.c \
	$(DIRME)/sha1.c $(DIRME)/pbkdf2_sha256.c $(DIRME)/lax_der_parsing.c \
	$(INC)/crypto_scrypt-nosse.c $(INC)/sha256.c \
	$(INC)/ethash/keccak.c $(INC)/ethash/keccakf1600.c

FILE_LIST += $(DIRSEC)/hash_impl.c $(DIRSEC)/modules/ecdh/main_impl.c $(DIRSEC)/gen_context.c $(DIRSEC)/secp256k1.c 

FILE_LIST += $(LOCAL_PATH)/nmw_wallet_core.cpp

LOCAL_SRC_FILES := $(FILE_LIST:$(LOCAL_PATH)/%=%)
# LOCAL_SRC_FILES := test.cpp

include $(BUILD_STATIC_LIBRARY)
# include $(BUILD_SHARED_LIBRARY)