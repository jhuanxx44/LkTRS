#include "lktrs.h"
#include <iostream>

int main() {
    // PBC Type A参数
    const char* param = "type a\n"
                        "q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791\n"
                        "h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776\n"
                        "r 730750818665451621361119245571504901405976559617\n"
                        "exp2 159\n"
                        "exp1 107\n"
                        "sign1 1\n"
                        "sign0 1\n";

    // 创建LkTRS实例
    LkTRS scheme(param, 5);  // k = 5表示最大签名次数

    // 初始化系统
    if (!scheme.Setup(256)) {
        std::cout << "Setup failed" << std::endl;
        return 1;
    }

    // 生成密钥对（生成账户）
    auto [pk, sk] = scheme.KeyGen();
    std::cout << "Key generation successful" << std::endl;

    // 生成n对密钥...
    constexpr int N = 10;
    std::vector<std::pair<PublicKey, SecretKey>> keys;
    std::vector<PublicKey> L;
    for(int i = 0; i < N; i++) {
        auto key_pair = scheme.KeyGen();
        keys.push_back(key_pair);
        L.push_back(key_pair.first);
    }

    // 签名
    std::string msg = "some transaction msg";
    int cnt = 0;
    element_t my_nym;
    auto sig = scheme.RSign(sk, pk, L, msg, cnt, my_nym);

    // 验证
    bool result = scheme.RVer(L, msg, my_nym, sig);
    if(result) {
        std::cout << "verify OK" << std::endl;
    } 
    else {
        std::cout << "verify failed" << std::endl;
    }

    element_clear(my_nym);
    return 0;
}

