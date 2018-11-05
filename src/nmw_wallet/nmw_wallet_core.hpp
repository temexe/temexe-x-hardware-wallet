#ifndef NMW_WALLET_CORE
#define NMW_WALLET_CORE

#include <string>
using namespace std;

namespace nmw_wallet
{

enum class COINTYPE : uint32_t
{
    BITCOIN = 0,
    BITCOIN_TESTNET = 1,
    ETHEREUM = 60,
};

class NmwWalletCore
{
  public:
    /*
        @return mnemonic, 12 words seperated by ' '
    */
    static string getMnemonic();

    /*
        @return address\nsecret_encoded
    */
    static string derivedPrivateByMnemonic(string mnemonic, string passphrase, string path);

    /*
        only for ethereum, not for bitcoin
        @return address\nsecret_encoded
    */
    static string derivedPrivateByKeystore(string keystore, string password);

    /*
        @return address\nsecret_encoded
    */
    static string derivedPrivateByKey(uint32_t cointype, string private_key);

    static string buildBtcRawTransaction(string net,string secretKey, string utxoJson);

    static string buildEthRawTransaction(string secretKey,string json);
    // static string buildEthRawTransaction(string secretKey, string to, string value, string nonce = "", string gasPrice = "", string gasLimit = "",string data="");

    // static string buildERC20Transfer(string secretKey,string contractAddress,string transferAddress,string value,string nonce, string gasPrice, string gasLimit);
};

} // namespace nmw_wallet

#endif