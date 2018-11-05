
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <sstream>

#include "nmw_wallet_core.hpp"
#include <bitcoin/bitcoin.hpp>
#include <libdevcore/Common.h>
#include <libdevcore/CommonJS.h>
#include <libethcore/CommonJS.h>
#include <libdevcrypto/Common.h>
#include <libdevcore/FixedHash.h>
#include <libdevcrypto/SecretStore.h>
#include <thread>
#include <mutex>
#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>
#include <libdevcore/Log.h>
#include <libdevcore/Guards.h>
#include <libdevcore/SHA3.h>
#include <libdevcore/FileSystem.h>
#include "boost/bind/placeholders.hpp"
#include <json_spirit/JsonSpiritHeaders.h>
#include <libdevcrypto/Exceptions.h>
#include <bitcoin/bitcoin/utility/data.hpp>

#include <algorithm>
#include <iomanip>
#include <cstdint>
#include <vector>
#include <boost/date_time.hpp>
#include <boost/format.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/info_parser.hpp>
#include <libethcore/Common.h>
#include <libethereum/Transaction.h>

#include <bitcoin/client.hpp>

#include "json/json.h"

using namespace bc;
using namespace wallet;
using namespace std;
using namespace nmw_wallet;
using namespace dev;
using namespace eth;
using namespace machine; //opcode
using namespace chain;   //transaction, inputs, outputs, script

namespace js = json_spirit;
namespace fs = boost::filesystem;

static const int c_keyFileVersion = 3;
#ifdef NMW_DEBUG
//osteam& nmout = nmout;
// ofstream testfout;
std::ofstream nmf("/tmp/tmpa.txt", std::ios::out);
ostream &nmout = nmf;
#endif

bytesSec eth_decrypt(string const &_v, string const &_pass)
{
    //TODO: ADD try catch
    js::mObject o, o2;
    {
        js::mValue ov;
        js::read_string(_v, ov);
        o2 = ov.get_obj();
        o = o2["crypto"].get_obj();
    }

    // derive key
    bytesSec derivedKey;
    if (o["kdf"].get_str() == "pbkdf2")
    {
        auto params = o["kdfparams"].get_obj();
        if (params["prf"].get_str() != "hmac-sha256")
        {
            // cwarn << "Unknown PRF for PBKDF2" << params["prf"].get_str() << "not supported.";
            return bytesSec();
        }
        unsigned iterations = params["c"].get_int();
        bytes salt = fromHex(params["salt"].get_str());
        derivedKey = pbkdf2(_pass, salt, iterations, params["dklen"].get_int());
    }
    else if (o["kdf"].get_str() == "scrypt")
    {
        auto p = o["kdfparams"].get_obj();
        derivedKey = scrypt(_pass, fromHex(p["salt"].get_str()), p["n"].get_int(), p["r"].get_int(), p["p"].get_int(), p["dklen"].get_int());
    }
    else
    {
        // cwarn << "Unknown KDF" << o["kdf"].get_str() << "not supported.";
        return bytesSec();
    }

    if (derivedKey.size() < 32 && !(o.count("compat") && o["compat"].get_str() == "2"))
    {
        // cwarn << "Derived key's length too short (<32 bytes)";
        return bytesSec();
    }

    bytes cipherText = fromHex(o["ciphertext"].get_str());

    // check MAC
    if (o.count("mac"))
    {
        h256 mac(o["mac"].get_str());
        h256 macExp;
        if (o.count("compat") && o["compat"].get_str() == "2")
            macExp = sha3(derivedKey.ref().cropped(derivedKey.size() - 16).toBytes() + cipherText);
        else
            macExp = sha3(derivedKey.ref().cropped(16, 16).toBytes() + cipherText);
        if (mac != macExp)
        {
            // cwarn << "Invalid key - MAC mismatch; expected" << toString(macExp) << ", got" << toString(mac);
            return bytesSec();
        }
    }
    else if (o.count("sillymac"))
    {
        h256 mac(o["sillymac"].get_str());
        h256 macExp = sha3(asBytes(o["sillymacjson"].get_str()) + derivedKey.ref().cropped(derivedKey.size() - 16).toBytes() + cipherText);
        if (mac != macExp)
        {
            // cwarn << "Invalid key - MAC mismatch; expected" << toString(macExp) << ", got" << toString(mac);
            return bytesSec();
        }
    }
    // else
    // 	cwarn << "No MAC. Proceeding anyway.";

    // decrypt
    if (o["cipher"].get_str() == "aes-128-ctr")
    {
        auto params = o["cipherparams"].get_obj();
        h128 iv(params["iv"].get_str());
        if (o.count("compat") && o["compat"].get_str() == "2")
        {
            SecureFixedHash<16> key(sha3Secure(derivedKey.ref().cropped(derivedKey.size() - 16)), h128::AlignRight);
            return decryptSymNoAuth(key, iv, &cipherText);
        }
        else
            return decryptSymNoAuth(SecureFixedHash<16>(derivedKey, h128::AlignLeft), iv, &cipherText);
    }
    else
    {
        // cwarn << "Unknown cipher" << o["cipher"].get_str() << "not supported.";
        return bytesSec();
    }
}

// static std::string normal_form(const std::string& value, norm_type form)
// {
//     auto backend = localization_backend_manager::global();
//     backend.select(BC_LOCALE_BACKEND);
//     const generator locale(backend);
//     return normalize(value, form, locale(BC_LOCALE_UTF8));
// }

// // One time verifier of the localization backend manager. This is
// // necessary because boost::normalize will fail silently to perform
// // normalization if the ICU dependency is missing.
// static void validate_localization()
// {
//     const auto ascii_space = "> <";
//     const auto ideographic_space = ">　<";
//     const auto normal = normal_form(ideographic_space, norm_type::norm_nfkd);

//     if (normal != ascii_space)
//         throw std::runtime_error(
//             "Unicode normalization test failed, a dependency may be missing.");
// }

// // Normalize strings using unicode nfc normalization.
// std::string to_normal_nfc_form(const std::string& value)
// {
//     std::call_once(icu_mutex, validate_localization);
//     return normal_form(value, norm_type::norm_nfc);
// }

// // Normalize strings using unicode nfkd normalization.
// std::string to_normal_nfkd_form(const std::string& value)
// {
//     std::call_once(icu_mutex, validate_localization);
//     return normal_form(value, norm_type::norm_nfkd);
// }

// long_hash decode_mnemonic2(const word_list& mnemonic,
//     const std::string& passphrase)
// {
//     int hmac_iterations = 2048;
//     const auto sentence = join(mnemonic);
//     const std::string prefix("mnemonic");
//     const auto salt = to_normal_nfkd_form(prefix + passphrase);
//     return pkcs5_pbkdf2_hmac_sha512(to_chunk(sentence), to_chunk(salt),
//         hmac_iterations);
// }

void trim(string &str)
{
    str.erase(0, str.find_first_not_of(" "));
    str.erase(str.find_last_not_of(" ") + 1);
}

/*
    @param path_item:  one item like 0' in a path
*/
int transBip44PathItem2Int(string path_item)
{
    trim(path_item);
    //find all numbers
    stringstream ss(path_item);
    int v;
    ss >> v;
    return v;
}

/**
 * @return address
 */

string _derivedPrivateByKey(uint32_t cointype, const ec_private &mc)
{

    //TODO: add judge cointype
    string address = "";


    // ec_private mc = (ec_private)m;
    
    if(cointype == static_cast<uint32_t>(COINTYPE::BITCOIN)){
        #ifdef NMW_DEBUG
        nmout<<"encoded private key: "<<mc.encoded()<<std::endl;
        #endif
        address = mc.to_payment_address().encoded();
    }
    else if(cointype == static_cast<uint32_t>(COINTYPE::BITCOIN_TESTNET)){
        address = mc.to_public().to_payment_address(ec_private::testnet_p2kh).encoded();
    }
    else if(cointype == static_cast<uint32_t>(COINTYPE::ETHEREUM)){

        ec_uncompressed ecm;
        mc.to_public().to_uncompressed(ecm);
        std::vector<uint8_t> epk(ecm.size()-1);
        for(int i=0; i<ecm.size()-1; i++){
            epk[i] = ecm[i+1];
        }
        address = dev::right160(dev::sha3(dev::FixedHash<64>(epk))).hex();

    }
    return address;
}

// string ETH_publicKey2Address(byte_array pubkey){
//     auto right160 = slice<12,32>(pubkey);

// }

/*
    @param cointype: trimed cointype like  1'
*/
// string hd_private2address(hd_private &m){

//     ec_compressed my_pubkey;
//     secret_to_public(my_pubkey, (ec_secret)m);

//     // Pubkeyhash: sha256 + hash160
//     auto my_pubkeyhash = bitcoin_short_hash(my_pubkey);

//     // Prefix for mainnet = 0x00
//     one_byte addr_prefix = { { 0x00 } }; //Testnet 0x6f

//     // Byte sequence = prefix + pubkey + checksum(4-bytes)
//     data_chunk prefix_pubkey_checksum(to_chunk(addr_prefix));
//     extend_data(prefix_pubkey_checksum, my_pubkeyhash);
//     append_checksum(prefix_pubkey_checksum);

//     // Base58 encode byte sequence -> Bitcoin Address
//     string address = encode_base58(prefix_pubkey_checksum);

//     return address;

// }

string NmwWalletCore::getMnemonic()
{

    data_chunk my_entropy_128(16); //16 bytes = 128 bits
    pseudo_random_fill(my_entropy_128);

    // Instantiate mnemonic word_list
    word_list my_word_list = create_mnemonic(my_entropy_128);
    return join(my_word_list); //join to a single string with spaces
}

string NmwWalletCore::derivedPrivateByKeystore(string keystore, string password)
{

    bytesSec bs = eth_decrypt(keystore, password);
    std::vector<uint8_t> bv = bs.makeInsecure();
    //to derive address
    ec_secret ecs;
    std::copy(bv.begin(), bv.end(), ecs.begin());
    ec_private mc(ecs);
    string address = _derivedPrivateByKey(static_cast<uint32_t>(COINTYPE::ETHEREUM), mc);
    return address + "\n" + encode_base16(ecs);
}

/**
    @return address
*/
string NmwWalletCore::derivedPrivateByKey(uint32_t cointype, string private_key)
{

    string address = "";
    
    if(cointype == static_cast<uint32_t>(COINTYPE::BITCOIN)){
        ec_private mc(private_key);
        address = _derivedPrivateByKey(cointype,mc);
    }
    else if(cointype == static_cast<uint32_t>(COINTYPE::BITCOIN_TESTNET)){
        data_chunk dc;
        decode_base58(dc,private_key);
        address = encode_base58(dc);
        ec_secret secret;
        copy(dc.begin()+1,dc.begin()+1+ec_secret_size,secret.begin());
        ec_private mc(secret,ec_private::testnet);
        address = _derivedPrivateByKey(cointype,mc);
    }
    else if(cointype == static_cast<uint32_t>(COINTYPE::ETHEREUM)){
        std::vector<uint8_t> out;
        decode_base16(out,private_key);
        ec_secret ecs;
        copy(out.begin(),out.end(),ecs.begin());
        //ec_secret to ec_private
        ec_private mc(ecs);
        address = _derivedPrivateByKey(cointype,mc);

    }
    return address;
}

string NmwWalletCore::derivedPrivateByMnemonic(string mnemonic, string passphrase, string Bip44Path)
{

    word_list path_elems = split(Bip44Path,"/",true);
    int path[256];
    int pathlen = 0;   
    if(path_elems.size() < 3){
        return "";
    }

    //construct path item in order
    for(int i=1; i<path_elems.size(); i++){
        path[i-1] = transBip44PathItem2Int(path_elems[i]);
        pathlen = i;    
    }
    
    if(pathlen < 5){
        return "";
    }

    int coin_type = path[1];
    //construct main private keys
    auto my_word_list = split(mnemonic, " ", true);
    auto hd_seed = decode_mnemonic(my_word_list,passphrase);
    data_chunk seed_chunk(to_chunk(hd_seed));
    uint64_t prefix = hd_private::mainnet;
    if(coin_type == 1)//testnet
    {
        prefix = hd_private::testnet;
    }
    hd_private m(seed_chunk,prefix);

    #ifdef NMW_DEBUG 
    nmout<<"root key: "<<m.encoded()<<std::endl;
    nmout <<"path: m "<<std::endl;
    #endif

    auto mc = m;

    int harden_start_index = 0x80000000;
    for(int i=0; i<pathlen; i++){
        if(i >= 3){
            harden_start_index = 0;
            // if(coin_type == 1 && i==4 ){//testnet
            //     harden_start_index =  0x80000000 + 1;
            // }
        }
        else{
            harden_start_index = 0x80000000;
            // if(i==1 && path[i] == 1){
            //     harden_start_index = harden_start_index +1;
            // }
        }
        mc = mc.derive_private(path[i]+harden_start_index);

        #ifdef NMW_DEBUG
        nmout<<" / "<<path[i];
        nmout<<"path priv key: "<<mc.encoded()<<std::endl;
        #endif
    }


    
    // hd_public MK = mc.to_public();
    // nmout<<"public: "<<MK.encoded()<<std::endl;
    // nmout<<"public_HD: "<<encode_base16(slice<45,78>(MK.to_hd_key()))<<std::endl;
    std::cout<<"public_HD 2: "<<encode_base16( (ec_compressed) ((ec_private)mc).to_public())<<std::endl;
    // nmout<<"private: "<<mc.encoded()<<std::endl;
    // nmout<<"private_HD_ALL: "<<encode_base16(mc.to_hd_key())<<std::endl;
    std::cout<<"private address: "<<((ec_private)mc).to_payment_address().encoded()<<std::endl;
    // // nmout<<"public_HD_LL: "<<encode_base16(MK.secret())<<std::endl;
    // nmout<<"private for ETH: "<<encode_base16(slice<46,78>(mc.to_hd_key()))<<std::endl;
    // int ver = ((ec_private)mc).payment_version();
    // nmout<<"payment version: "<<ver<<std::endl;
    // nmout<<"payment address without version: "<<((ec_public)MK).to_payment_address().encoded()<<std::endl;
    // nmout<<"payment address with version: "<<((ec_public)MK).to_payment_address(((ec_private)mc).payment_version()).encoded()<<std::endl;
    // nmout<<"payment address with prefix: "<<((ec_public)MK).to_payment_address(((ec_private)mc).to_address_prefix(((ec_private)mc).version())).encoded()<<std::endl;
    // nmout<<"payment address shorthash: "<<encode_base16((short_hash)((ec_public)MK).to_payment_address(((ec_private)mc).payment_version()))<<std::endl;
    // nmout<<"payment address hash58: "<<encode_base58((short_hash)((ec_public)MK).to_payment_address(((ec_private)mc).payment_version()))<<std::endl;
    
    // string address = ((ec_public)MK).to_payment_address(((ec_private)mc).payment_version()).encoded();// 
    string secret = ((ec_private)mc).encoded();
    if(coin_type == static_cast<uint32_t>(COINTYPE::ETHEREUM)){
        secret = encode_base16(mc.secret());
    }else if(coin_type == static_cast<uint32_t>(COINTYPE::BITCOIN_TESTNET)){
        uint8_t secret_prefix = 0xef; //{ { 0x80 } }; //Testnet Prefix: 0xEF
        one_byte secret_compressed = { { 0x01} }; //Omitted if uncompressed
        // Apply prefix, suffix & append checksum
        auto prefix_secret_comp_checksum = to_chunk(secret_prefix);
        extend_data(prefix_secret_comp_checksum, mc.secret());
        extend_data(prefix_secret_comp_checksum, secret_compressed);
        append_checksum(prefix_secret_comp_checksum);

        // WIF (mainnet/compressed)
        secret = encode_base58(prefix_secret_comp_checksum);
    }else if (coin_type == static_cast<uint32_t>(COINTYPE::BITCOIN)){

        uint8_t secret_prefix = 0x80;
        one_byte secret_compressed = { { 0x01} }; //Omitted if uncompressed
        // Apply prefix, suffix & append checksum
        auto prefix_secret_comp_checksum = to_chunk(secret_prefix);
        extend_data(prefix_secret_comp_checksum, mc.secret());
        extend_data(prefix_secret_comp_checksum, secret_compressed);
        append_checksum(prefix_secret_comp_checksum);

        // WIF (mainnet/compressed)
        secret = encode_base58(prefix_secret_comp_checksum);
    }


    string address = _derivedPrivateByKey(path[1],(ec_private)mc);

    return address+"\n"+secret;
}

transaction makeInput(payment_address fromAddress, transaction tx,Json::Value utxos)
{
    input::list inputs{};


    for(int i=0;i<utxos.size();i++)    {
        string hash=utxos[i]["txHash"].asString();
        
        uint64_t prev_output_index=utxos[i]["txIndex"].asLargestUInt();
        std::cout << prev_output_index << std::endl;
        char tmp[65] = {0};
        if(hash.size() == 64)
            strncpy(tmp,hash.c_str(),64);
        tmp[64] = 0;

        auto hash1 = hash_literal(tmp);
        input workingInput = input();
        chain::point value(hash1, prev_output_index);
        chain::output_point utxo(value);
        workingInput.set_previous_output(output_point(utxo));

        workingInput.set_script(script(script().to_pay_key_hash_pattern(fromAddress.hash())));
        workingInput.set_sequence(0xffffffff);
        inputs.push_back(workingInput);    
    }
    
     // auto hash1 = hash_literal("2864db14ff9a79a45cbd7f16f70e866f92c639b325e94420343c8ede7d50463f");
     //    input workingInput = input();
     //    chain::point value(hash1, 0);
     //    chain::output_point utxo(value);
     //    workingInput.set_previous_output(output_point(utxo));

     //    workingInput.set_script(script(script().to_pay_key_hash_pattern(fromAddress.hash())));
     //    workingInput.set_sequence(0xffffffff);
     //    inputs.push_back(workingInput);

    extend_data(tx.inputs(), inputs);

    return tx;
}

TransactionSkeleton toTransactionSkeleton(string from, string to, string value, string nonce, string gasPrice, string gasLimit,string data)
{
    TransactionSkeleton ret;

    if (!from.empty())
        ret.from = jsToAddress(from);
    if (!to.empty() && to != "0x")
        ret.to = jsToAddress(to);
    else
        ret.creation = true;

    if (!value.empty())
        ret.value = jsToU256(value);

    if (!gasLimit.empty())
        ret.gas = jsToU256(gasLimit);

    if (!gasPrice.empty())
        ret.gasPrice = jsToU256(gasPrice);

    if (!nonce.empty())
        ret.nonce = jsToU256(nonce);
    
    if (!data.empty())                            // ethereum.js has preconstructed the data array
        ret.data = jsToBytes(data, OnFailed::Throw);



    return ret;
}
double stringToDouble(string num)
{
    bool minus = false;      //标记是否是负数  
    string real = num;       //real表示num的绝对值
    if (num.at(0) == '-')
    {
        minus = true;
        real = num.substr(1, num.size()-1);
    }

    char c;
    int i = 0;
    double result = 0.0 , dec = 10.0;
    bool isDec = false;       //标记是否有小数
    unsigned long size = real.size();
    while(i < size)
    {
        c = real.at(i);
        if (c == '.')
        {//包含小数
            isDec = true;
            i++;
            continue;
        }
        if (!isDec) 
        {
            result = result*10 + c - '0';
        }
        else
        {//识别小数点之后都进入这个分支
            result = result + (c - '0')/dec;
            dec *= 10;
        }
        i++;
    }

    if (minus == true) {
        result = -result;
    }

    return result;
}
string doubleToString(double num)
{
    char str[256];
    sprintf(str, "%lf", num);
    string result = str;
    return result;
}
string NmwWalletCore::buildEthRawTransaction(string secretKey, string jsonStr)
{
    Secret secret(secretKey);
//string to, string value, string nonce, string gasPrice, string gasLimit,string data
    Json::Value json;
    
    Json::CharReaderBuilder builder;
    builder["collectComments"] = false;
    JSONCPP_STRING errs;
    Json::CharReader* reader = builder.newCharReader();

    if (!reader->parse(jsonStr.data(), jsonStr.data() + jsonStr.size(), &json, &errs)) //从jsonStr中读取数据到jsonRoot
    {
        cout << "parse error" << endl;
        return "";
    }

    string to=json["to"].asString();
    string value=json["value"].asString();
    string nonce=json["nonce"].asString();
    string gasPrice=json["gasPrice"].asString();
    string gasLimit=json["gasLimit"].asString();
    string data=json["data"].asString();

    //判断是否是ERC20交易   如果是重新计算data和value值 和to
    if(!json["contractAddress"].asString().empty()){
        to=json["contractAddress"].asString();

        h256 method=dev::sha3("transfer(address,uint256)");
        data=method.hex().substr(0,8);

        string transferAddress=json["to"].asString();
        //address
        if(transferAddress.find("0x")!=-1){
            transferAddress = transferAddress.replace(transferAddress.find("0x"), 2, "");    
        }

        string pending="";
        if(transferAddress.length()<64){
            pending.resize(64-transferAddress.length(),'0');    
        }
        
        data=data+pending+transferAddress;

        std::cout<< data <<std::endl;

        //value
        pending="";
        // double value_d=stringToDouble(value);
        // value="";
        // value_d=value_d*pow(10,18);
        // string value_s=doubleToString(value_d);
        string value_s=value;

        std::cout<< value_s <<std::endl;
        
        if(value_s.find(".")!=-1){
            value_s=value_s.substr(0,value_s.find("."));
        }
        
        u256 amount = jsToU256(value_s);

        std::cout<< amount <<std::endl;
       
        string amountHex=toCompactHex(amount);
        if(amountHex.length()<64){
            pending.resize(64-amountHex.length(),'0');    
        }

        data=data+pending+amountHex;
        TransactionSkeleton t = toTransactionSkeleton(toAddress(secret).hex(), to, "0", nonce, gasPrice, gasLimit,data);
        Transaction tran(t, secret);
        return toHex(tran.rlp());
    }

    TransactionSkeleton t = toTransactionSkeleton(toAddress(secret).hex(), to, value, nonce, gasPrice, gasLimit,data);
    Transaction tran(t, secret);
    return toHex(tran.rlp());


}

string NmwWalletCore::buildBtcRawTransaction(string netStr,string secretKey,string utxoJson)
{
    uint8_t net=0;
    if(netStr=="testnet"){
        net=0x6f;
    }else if(netStr=="mainnet"){
        net=0x00;
    }

    Json::Value list;

    Json::CharReaderBuilder builder;
    builder["collectComments"] = false;
    JSONCPP_STRING errs;
    Json::CharReader* reader = builder.newCharReader();

    if (!reader->parse(utxoJson.data(), utxoJson.data() + utxoJson.size(), &list, &errs)) //从jsonStr中读取数据到jsonRoot
    {
        cout << "parse error" << endl;
        return "";
    }
    
    ec_secret secret;
    wallet::ec_public ecPublic;
    data_chunk pubkey1;

    if(secretKey.length()==52){
        std::cout << "wif" << std::endl;
        //wif 
        wallet::ec_private ecPrivate=wallet::ec_private(secretKey);
        secret=ecPrivate.secret();
        ecPublic=ecPrivate.to_public();
        pubkey1 = to_chunk(ecPublic.point());
    }else{
        std::cout << "hd" << std::endl;
        //hd child key
        wallet::hd_private privateKey = wallet::hd_private(secretKey);
        secret=privateKey.secret();
        wallet::hd_public publicKey = privateKey.to_public();
        ecPublic=wallet::ec_public(publicKey.point());
        pubkey1 = to_chunk(publicKey.point());
    }

    wallet::payment_address fromAddress = wallet::payment_address(ecPublic, net);
    std::cout << fromAddress.encoded() << std::endl;

    transaction coinJoin = transaction();
    coinJoin.set_version(2);
    //make output
    for(int i=0;i<list["output"].size();i++){
        // std::cout << list["output"][i]["toAddress"].asString() << std::endl;
        payment_address destination1(list["output"][i]["toAddress"].asString());
        script outputScript = script().to_pay_key_hash_pattern(destination1.hash());
        output output1(list["output"][i]["value"].asLargestUInt(), outputScript);
        coinJoin.outputs().push_back(output1);
    }

    //make input 
    coinJoin = makeInput(fromAddress, coinJoin, list["input"]);

    script lockingScript = script().to_pay_key_hash_pattern(bitcoin_short_hash(pubkey1));

    int index = 0;
    for (auto input: coinJoin.inputs())
    {
        if(input.script() == script(lockingScript))
        {
            endorsement sig;
            if(lockingScript.create_endorsement(sig, secret, lockingScript , coinJoin, index, all_anyone_can_pay)){
                std::cout << "Signature: " << std::endl;
                std::cout << encode_base16(sig) << "\n" << std::endl;   
            }
            operation::list ops {operation(sig), operation(pubkey1)};
            script scriptSig(ops);
            input.script().clear();
            input.set_script(scriptSig);
            coinJoin.inputs()[index] = input;
        }
        index++;
    }
    return encode_base16(coinJoin.to_data());
}
