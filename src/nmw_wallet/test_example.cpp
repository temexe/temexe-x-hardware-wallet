#include <cstdlib>
#include <algorithm>  
#include <functional>  
#include <string>
#include <vector>

#include <bitcoin/bitcoin.hpp>
#include "nmw_wallet_core.hpp"
// #include "NmwTransaction.hpp"


using namespace nmw_wallet;
BC_USE_LIBBITCOIN_MAIN

void done(const string& msg){
    std::cout<<"###############"<<msg<<"  OK ################"<<std::endl;
}

#define WARN_COMP_STR(exp1,exp2,msg) \
    if(exp1 != exp2) { std::cout<<msg<<" -->"<<std::endl<<exp1<<std::endl<<"not equal"<<std::endl<<exp2<<std::endl; exit(1);}

void warndie(bool isWrong, string msg){

    if(isWrong){
        std::cout<<msg<<endl;
        exit(1);
    }

}


void Test_getMnemonic(){

    //std::cout<<"call NmwWalletCore::getMnemonic()"<<std::endl;
    string mnemonic = NmwWalletCore::getMnemonic();
    libbitcoin::string_list wl = libbitcoin::split(mnemonic," ",true);
    warndie(wl.size() != 12,"getMnemonic returns not 12 words: "+mnemonic);
    done("TEST_getMnemonic");
}

void Test_derivedPrivateByMnemonic(){

    // std::cout<<"################################"<<std::endl;
    // std::cout<<"call derivedPrivateByMnemonic"<<std::endl;
    string mnemonic = "lonely town van brave deal market flip crouch odor flash dash whip";
    string passphrase = "";
    string _path = "m / 44' / 0' / 0' / 0 / 0";
//#define TESTK(_path, _expect) \
//    WARN_COMP_STR(NmwWalletCore::derivedPrivateByMnemonic(mnemonic,passphrase,_path),_expect, _path);
    string sy = NmwWalletCore::derivedPrivateByMnemonic(mnemonic,passphrase,_path);
    std::cout<< sy <<std::endl;
//
//    TESTK("m / 44' / 1' / 0' / 0 / 0", "muLhAXbcCdQMKtuUV6Up2iNXCkxuMDPeQ6\ncRmtfpbQ1M81DHX8zVnEiZDfviYUUNP875z5DCsffjvhwVMdDWoe");
//    TESTK("m / 44' / 1' / 0' / 0 / 3", "mxxDhEwsegGSSyhoNBKwQh6UjZ2gx1V9sA\ncRoVrFeqAKFe6NsZ1ob9ovfQ7AC7Nnbfp5JHdAHMEHB9uxR8bQF6");
//    TESTK("m / 44' / 1' / 0' / 0 / 10", "mvoRAVYQ75N2zEn9zXPR6zTaWFLGJxqt4b\ncT3rtGquxyBy8AAyQtCm8nhrME1STxi5fHTxmcMELdMs5Q7ov3gh");
//    TESTK("m / 44' / 1' / 0' / 0 / 19", "ms6DLH4cMrTWgen1V1rf7UMmAgT9yLVn8A\ncRvh8daEBUybdihatXouYcVxGubD1FE3SHZuwRrFijwx5yaEcLb7");
//
//    TESTK("m / 44' / 0' / 0' / 0 / 0", "1LpGKF5fkTGZoEwQ3GSKJs64N3pQBgmWTq\nL2kxPpPHVg2ugxxSrvJ4J2Vgjbp7n77RKz9dupzDW7AtQRszjskE");
//    TESTK("m / 44' / 0' / 0' / 0 / 11", "15WjXDL4QTtGRF6o93TTi54QzpxF3NmCCs\nL2dXGshWTiekE2k8ANBZsgQjhwyk7Q4Pf2ET9Au4ADXVc7WBsnmc");
//    TESTK("m / 44' / 0' / 0' / 1 / 14", "13JLsTWPWt7RpFcak5FCmDGiEh81dANZ3L\nL25jYeKjjNqCrspdH9Zbw3KCnnskEpdk5qmFUAoLLFE3SJS3BiFq");
//    TESTK("m / 44' / 0' / 0' / 1 / 5", "1EeqGgQdVWBrsQkA8FaSULWu2ucHhLdGWj\nL5RhnzjndCrHZBzk1Rx77ZtdBJB9LiXWY4akcuytYptVznjqJ3ie");
//    TESTK("m / 44' / 60' / 1' / 1 / 7", "6a715cb5155858df5024802abc792e10fbec7c57\n4d42eb77f1bea9f4afe9c5e2631d12100b48c3f4a409bebd534439cc679b0336");
//    TESTK("m / 44' / 60' / 0' / 1 / 12", "6329a9687c20c76487a83e03d12a31ae30f68950\n85349e88aa838e9bbef1b5e9112e64a7451fc7e9dffdc8e7cb29ae81cf445fad");
//    TESTK("m / 44' / 60' / 0' / 0 / 17", "943ea03018dce3d8a4183455e530ebe0f6853d15\n6b1833cbb0f2a22751872925f513fecb27a9dd5a79cf5dec2716314312679271");
    done("Test_derivedPrivateByMnemonic");
}

void Test_derivedPrivateByKey(){

#define TEST_DR(cointype,address,privkey) \
    WARN_COMP_STR(NmwWalletCore::derivedPrivateByKey(60,"2bb9dae4328f4d9be8215e938d76461ff9aeb63d6ceea68b381ff36f6bb2fb7e"),address, privkey);
//TEST_DR(1,"muLhAXbcCdQMKtuUV6Up2iNXCkxuMDPeQ6","cRmtfpbQ1M81DHX8zVnEiZDfviYUUNP875z5DCsffjvhwVMdDWoe")
//TEST_DR(1,"mxxDhEwsegGSSyhoNBKwQh6UjZ2gx1V9sA","cRoVrFeqAKFe6NsZ1ob9ovfQ7AC7Nnbfp5JHdAHMEHB9uxR8bQF6")
//TEST_DR(1,"mvoRAVYQ75N2zEn9zXPR6zTaWFLGJxqt4b","cT3rtGquxyBy8AAyQtCm8nhrME1STxi5fHTxmcMELdMs5Q7ov3gh")
//TEST_DR(1,"ms6DLH4cMrTWgen1V1rf7UMmAgT9yLVn8A","cRvh8daEBUybdihatXouYcVxGubD1FE3SHZuwRrFijwx5yaEcLb7")
//
//TEST_DR(0,"1LpGKF5fkTGZoEwQ3GSKJs64N3pQBgmWTq","L2kxPpPHVg2ugxxSrvJ4J2Vgjbp7n77RKz9dupzDW7AtQRszjskE")
//TEST_DR(0,"15WjXDL4QTtGRF6o93TTi54QzpxF3NmCCs","L2dXGshWTiekE2k8ANBZsgQjhwyk7Q4Pf2ET9Au4ADXVc7WBsnmc")
//TEST_DR(0,"13JLsTWPWt7RpFcak5FCmDGiEh81dANZ3L","L25jYeKjjNqCrspdH9Zbw3KCnnskEpdk5qmFUAoLLFE3SJS3BiFq")
//                                       f253951acf464294fe1be924c9159cf21203a0dd7a2d052b244a6d002b073039
//TEST_DR(0,"1EeqGgQdVWBrsQkA8FaSULWu2ucHhLdGWj","L5RhnzjndCrHZBzk1Rx77ZtdBJB9LiXWY4akcuytYptVznjqJ3ie")
//TEST_DR(60,"6a715cb5155858df5024802abc792e10fbec7c57","4d42eb77f1bea9f4afe9c5e2631d12100b48c3f4a409bebd534439cc679b0336")
//TEST_DR(60,"6329a9687c20c76487a83e03d12a31ae30f68950","85349e88aa838e9bbef1b5e9112e64a7451fc7e9dffdc8e7cb29ae81cf445fad")
TEST_DR(60,"53a2bed7c99307b0d971a39ec3cefec74c869f7d","f253951acf464294fe1be924c9159cf21203a0dd7a2d052b244a6d002b073039")
done("Test_derivedPrivateByKey");
}

void TEST_derivedPrivateByKeystore(){

#define TEST_DS(keystore,pass,result) \
    WARN_COMP_STR(NmwWalletCore::derivedPrivateByKeystore(keystore,pass),result, keystore);
       
    string keyData = R"({
        "version": 3,
        "crypto": {
            "ciphertext": "d69313b6470ac1942f75d72ebf8818a0d484ac78478a132ee081cd954d6bd7a9",
            "cipherparams": { "iv": "ffffffffffffffffffffffffffffffff" },
            "kdf": "pbkdf2",
            "kdfparams": { "dklen": 32,  "c": 262144,  "prf": "hmac-sha256",  "salt": "c82ef14476014cbf438081a42709e2ed" },
            "mac": "cf6bfbcc77142a22c4a908784b4a16f1023a1d0e2aff404c20158fa4f1587177",
            "cipher": "aes-128-ctr",
            "version": 1
        },
        "id": "abb67040-8dbe-0dad-fc39-2b082ef0ee5f"
    })";


TEST_DS(keyData,"bar","5050a4f4b3f9338c3472dcc01a87c76a144b3c9c\n0202020202020202020202020202020202020202020202020202020202020202");
done("TEST_derivedPrivateByKeystore");
}


string testEthereum(){

    string secretKey="35ca1d38308a02054609811e7c7bfc6d8e426e47451a036d0c04f906a593758a";

    string json="{\"data\":\"\",\"contractAddress\":\"\",\"gasLimit\":21000,\"value\":100000000000000000,\"to\":\"0x56a92690b2967d647038a2afdeca137ba5fa8658\",\"gasPrice\":1200000000,\"nonce\":0}";
    string sign = NmwWalletCore::buildEthRawTransaction(secretKey,json);
    std::cout<< sign<<std::endl;
    done("testEthereum");
    return sign;
}

string testERC20Transfer(){
    string secretKey="f253951acf464294fe1be924c9159cf21203a0dd7a2d052b244a6d002b073039";

    string json="{\"gasLimit\":200000,\"data\":\"\",\"contractAddress\":\"0xd850942ef8811f2a866692a623011bde52a462c1\",\"to\":\"0xebabea1b77c9e3a2e1bf404cf5f8f4400fe3cbf4\",\"value\":100000000000000000,\"nonce\":25,\"gasPrice\":20000000000}";
    string sign = NmwWalletCore::buildEthRawTransaction(secretKey,json);
    std::cout<< sign<<std::endl;
    // done("testEthereum");
    return "";   
}

string testBitcoin(){

//    string net="testnet";
     string net="mainnet";
    //hd private key
//    string secretKey="xprv9uBFXrfde1nkP91P7ALdZdRgn6vWuXEMGmC2vsWiYax88vP6nhvX1s5hV8oFx2gitBTLqrvccd5TqqKxdoD5n7jzJUuQvQYsDwMRjvu7C9Z";
   
    //wif private key
     string secretKey="Kwtv6Aa8cSP6gBgkZAwBe7bWgtaDjrhVAveEeuYcBWDmCiATBY6k";

    string utxoJson="{\"output\":[{\"toAddress\":\"18RytwWW2a1p4VpqCoeip6EL7FVkz7BfUi\",\"value\":2500},{\"toAddress\":\"15MTsD5xkG2XhizSarJoaKx7wuArTrd4ff\",\"value\":27500}],\"input\":[{\"txHash\":\"0cf14ebf75fae04970a3d6fb5049ae9cf9630c7e13cc69a115d43ff01969ce01\",\"txIndex\":1,\"value\":40000}]}";
    // string utxoJson="{\"input\":[{\"txHash\": \"0abbf7a6d1467d9104494287fecad2d403a9e40734ae9896d36f05a996cae676\",\"txIndex\": 0}],\"output\":[{\"toAddress\": \"muh4t1FQC5onS9u7xfCXB7p9WfzAYKYCv1\",\"value\": 9990000},{\"toAddress\":\"mxXwFP4LEjRTtW2Busuxux8gmtsjJSTAAg\",\"value\": 100000000}]}";
    string sign=NmwWalletCore::buildBtcRawTransaction(net,secretKey,utxoJson).c_str();
    std::cout<< sign<<std::endl;
    done("testBitcoin");
    return sign;
}


int bc::main(int argc, char* argv[])
{

    
//    Test_getMnemonic();
    Test_derivedPrivateByKey();
//    Test_derivedPrivateByMnemonic();
//    TEST_derivedPrivateByKeystore();
//    testEthereum();
//    testERC20Transfer();
//    testBitcoin();
    std::cout<<"######################TEST DONE, ALL OK##########################"<<std::endl;
    return 0;
}