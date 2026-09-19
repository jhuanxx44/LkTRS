#include "spk.h"

SPK::SPK(SecretKey* sk, PublicKey* pk, int cnt, pairing_t pairing) :
    sk(sk),
    pk(pk),
    cnt(cnt)
{
    element_init_G1(w, pairing);
    element_random(w);  // 随机生成元素 u
}

SPK::~SPK() {
    element_clear(w);
}

// TODO...
SPKProof SPK::genProof() {
    return SPKProof();
}

// TODO. Note that this function is parameters irrelevant
bool SPK::verify(const SPKProof &p) {
    return false;
} 